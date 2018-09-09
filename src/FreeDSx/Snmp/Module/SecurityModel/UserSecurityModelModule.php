<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Module\SecurityModel;

use FreeDSx\Snmp\Exception\RediscoveryNeededException;
use FreeDSx\Snmp\Exception\RuntimeException;
use FreeDSx\Snmp\Exception\SecurityModelException;
use FreeDSx\Snmp\Exception\SnmpAuthenticationException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\SecurityModel\Usm\TimeSync;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\Factory\AuthenticationModuleFactory;
use FreeDSx\Snmp\Protocol\Factory\PrivacyModuleFactory;
use FreeDSx\Snmp\Protocol\IdGeneratorTrait;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Response\ReportResponse;

/**
 * Handles User based Security Model functionality for incoming / outgoing messages.
 *
 * RFC 3414.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class UserSecurityModelModule implements SecurityModelModuleInterface
{
    use IdGeneratorTrait;

    protected const TIME_WINDOW = 150;

    protected const USM_UNKNOWN_ENGINE_ID = '1.3.6.1.6.3.15.1.1.4.0';

    protected const USM_NOT_IN_TIME_WINDOW = '1.3.6.1.6.3.15.1.1.2.0';

    protected const USM_WRONG_DIGEST = '1.3.6.1.6.3.15.1.1.5.0';

    protected const USM_DECRYPT_ERROR = '1.3.6.1.6.3.15.1.1.6.0';

    protected const ERROR_MAP_CLEAR_TIME = [
        self::USM_WRONG_DIGEST,
        self::USM_DECRYPT_ERROR,
    ];

    protected const ERROR_MAP_USM = [
        '1.3.6.1.6.3.15.1.1.1.0' => 'The requested security level was unknown or unavailable (usmStatsUnsupportedSecLevels).',
        '1.3.6.1.6.3.15.1.1.3.0' => 'The username was not recognized (usmStatsUnknownUserNames).',
        self::USM_WRONG_DIGEST => 'The message did not contain the correct digest (usmStatsWrongDigests).',
        self::USM_DECRYPT_ERROR => 'The message could not be decrypted (usmStatsDecryptionErrors).',
    ];

    /**
     * @var PrivacyModuleFactory
     */
    protected $privacyFactory;

    /**
     * @var AuthenticationModuleFactory
     */
    protected $authFactory;

    /**
     * @var TimeSync[]
     */
    protected $engineTime = [];

    /**
     * @var EngineId[]
     */
    protected $knownEngines = [];

    /**
     * @param PrivacyModuleFactory|null $privacy
     * @param AuthenticationModuleFactory|null $auth
     * @param array $engineTimes
     * @param array $knownEngines
     */
    public function __construct(?PrivacyModuleFactory $privacy = null, ?AuthenticationModuleFactory $auth = null, array $engineTimes = [], array $knownEngines = [])
    {
        $this->privacyFactory = $privacy ?: new PrivacyModuleFactory();
        $this->authFactory = $auth ?: new AuthenticationModuleFactory();
        $this->engineTime = $engineTimes;
        $this->knownEngines = $knownEngines;
    }

    /**
     * {@inheritdoc}
     */
    public function handleIncomingMessage(AbstractMessageV3 $message, array $options) : AbstractMessageV3
    {
        $securityParams = $message->getSecurityParameters();
        $header = $message->getMessageHeader();
        $pduFactory = $message instanceof MessageRequestInterface ? ScopedPduRequest::class : ScopedPduResponse::class;

        if (!$securityParams) {
            throw new SecurityModelException('The received SNMP message is missing the security parameters.');
        }
        if ($options['use_auth'] && !$header->hasAuthentication()) {
            throw new SecurityModelException('Authentication was requested, but the received header has none specified.');
        }
        if ($options['use_priv'] && !$header->hasPrivacy()) {
            throw new SecurityModelException('Privacy was requested, but the received header has none specified.');
        }

        if ($options['use_auth']) {
            try {
                $message = $this->authFactory->get($options['auth_mech'])->authenticateIncomingMsg(
                    $message,
                    $options['auth_pwd']
                );
            } catch (SnmpAuthenticationException $e) {
                throw new SecurityModelException($e->getMessage());
            }
        }
        if ($options['use_priv']) {
            $decryptedPdu = $this->privacyFactory->get($options['priv_mech'])->decryptData(
                $message,
                $this->authFactory->get($options['auth_mech']),
                $options['priv_pwd']
            );

            $requestObject = new \ReflectionObject($message);
            $pduProperty = $requestObject->getProperty('scopedPdu');
            $pduProperty->setAccessible(true);
            $pduProperty->setValue(
                $message,
                call_user_func($pduFactory.'::fromAsn1', (new SnmpEncoder())->decode($decryptedPdu))
            );

            $encryptedProperty = $requestObject->getProperty('encryptedPdu');
            $encryptedProperty->setAccessible(true);
            $encryptedProperty->setValue($message, null);
        }

        if ($message instanceof MessageResponseInterface) {
            $this->validateIncomingResponse($message, $options);
        }

        return $message;
    }

    /**
     * {@inheritdoc}
     */
    public function handleOutgoingMessage(AbstractMessageV3 $message, array $options) : AbstractMessageV3
    {
        $engineId = $this->getOutgoingEngineId($message, $options);
        $header = $message->getMessageHeader();
        $user = $options['user'] ?? '';

        # A trap does not do time discovery. Both get set to zero.
        if ($this->isTrapRequest($message)) {
            $engineBoot = 0;
            $engineTime = 0;
        } else {
            $cachedTime = $this->getEngineTime($engineId);
            $engineBoot = $cachedTime->getEngineBoot();
            $engineTime = $cachedTime->getEngineTime();
        }
        $usm = new UsmSecurityParameters(
            $engineId,
            $engineBoot,
            $engineTime,
            $user
        );

        $message->setSecurityParameters($usm);
        $message->setEncryptedPdu(null);
        $message->getScopedPdu()->setContextEngineId($engineId);
        $header->setSecurityModel($message->getSecurityParameters()->getSecurityModel());

        if ($header->hasPrivacy()) {
            $password = $options['priv_pwd'] ?? '';
            $this->privacyFactory->get($options['priv_mech'])->encryptData(
                $message,
                $this->authFactory->get($options['auth_mech']),
                $password
            );
        }

        if ($header->hasAuthentication()) {
            $password = $options['auth_pwd'] ?? '';
            $this->authFactory->get($options['auth_mech'])->authenticateOutgoingMsg($message, $password);
        }

        return $message;
    }

    /**
     * @param AbstractMessageV3 $messageV3
     * @param array $options
     * @return bool
     */
    public function isDiscoveryNeeded(AbstractMessageV3 $messageV3, array $options) : bool
    {
        $usm = $messageV3->getSecurityParameters();
        $host = $options['host'] ?? '';
        if ($this->isTrapRequest($messageV3)) {
            return false;
        }
        $engineId = $this->getEngineIdFromOptions($options);
        if ($usm instanceof UsmSecurityParameters && $usm->getEngineId()) {
            $engineId = $usm->getEngineId();
        }
        if ($engineId === null && array_key_exists($host, $this->knownEngines)) {
            $engineId = $this->knownEngines[$host];
        }

        # Not a known engineId, either for this host or otherwise. No engineId specifically used. Discovery needed...
        if ($engineId === null) {
            return true;
        }

        # Time was never cached for the engine, so discovery is required...
        if (!$this->isEngineTimeCached($engineId)) {
            return true;
        }
        $time = $this->getEngineTime($engineId);

        # If the time window is 150 seconds or more out, then force a resynchronization
        if (((new \DateTime())->getTimestamp() - $time->getWhenSynced()->getTimestamp()) >= self::TIME_WINDOW) {
            return true;
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getDiscoveryRequest(AbstractMessageV3 $messageV3, array $options): MessageRequestInterface
    {
        $engineId = $this->getEngineIdFromOptions($options);

        return new MessageRequestV3(
            new MessageHeader($this->generateId(1), MessageHeader::FLAG_REPORTABLE, $messageV3->getMessageHeader()->getSecurityModel()),
            new ScopedPduRequest(new GetRequest(new OidList()), $engineId),
            null,
            new UsmSecurityParameters($engineId, 0, 0)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function handleDiscoveryResponse(AbstractMessageV3 $message, MessageResponseInterface $discoveryResponse, array $options): AbstractMessageV3
    {
        $usm = $discoveryResponse->getSecurityParameters();
        $response = $discoveryResponse->getResponse();
        $host = $options['host'] ?? '';
        if (!($usm instanceof UsmSecurityParameters && $usm->getEngineId())) {
            throw new SecurityModelException('Failed to discover the engine id for USM.');
        }
        if (!$response instanceof ReportResponse) {
            throw new SecurityModelException(sprintf(
                'Failed to discover the engine id for USM. Expected a report response, got %s',
                get_class($response)
            ));
        }
        if (!$response->getOids()->has(self::USM_UNKNOWN_ENGINE_ID)) {
            throw new SecurityModelException('Expected an usmStatsUnknownEngineIDs OID, but none was received.');
        }
        $this->knownEngines[$host] = $usm->getEngineId();
        $this->engineTime[$usm->getEngineId()->toBinary()] = new TimeSync($usm->getEngineBoots(), $usm->getEngineTime());

        return $message;
    }

    /**
     * {@inheritdoc}
     */
    public static function supports() : int
    {
        return 3;
    }

    /**
     * @param MessageResponseInterface $response
     * @param array $options
     * @throws RediscoveryNeededException
     * @throws SecurityModelException
     */
    protected function validateIncomingResponse(MessageResponseInterface $response, array $options) : void
    {
        if (!$response->getResponse() instanceof ReportResponse) {
            return;
        }
        /** @var UsmSecurityParameters $secParams */
        $secParams = $response->getSecurityParameters();
        $knownEngine = $this->getEngineIdForHost($options['host']);

        if ($knownEngine === null || $secParams->getEngineId()->toBinary() !== $knownEngine->toBinary()) {
            throw new SecurityModelException('The expected engine ID does not match the known engine ID for this host.');
        }
        if ($response->getResponse()->getOids()->has(self::USM_NOT_IN_TIME_WINDOW)) {
            throw new RediscoveryNeededException($response, sprintf(
                'Encountered usmStatsNotInTimeWindow. Reported engine time is %s.',
                $secParams->getEngineTime()
            ));
        }
        foreach ($response->getResponse()->getOids() as $oid) {
            if (array_key_exists($oid->getOid(), self::ERROR_MAP_USM)) {
                # This will force a re-sync for the next request if we have already cached time info..
                if (in_array($oid->getOid(), self::ERROR_MAP_CLEAR_TIME) && $this->isEngineTimeCached($secParams->getEngineId())) {
                    $this->clearCachedEngine($secParams->getEngineId());
                }
                throw new SecurityModelException(self::ERROR_MAP_USM[$oid->getOid()]);
            }
        }
        if ($response->getResponse()->getOids()->has(self::USM_NOT_IN_TIME_WINDOW)) {
            throw new RediscoveryNeededException($response, sprintf(
                'Encountered usmStatsNotInTimeWindow. Reported engine time is %s.',
                $secParams->getEngineTime()
            ));
        }
    }

    /**
     * @param string $host
     * @return null|EngineId
     */
    protected function getEngineIdForHost(string $host) : ?EngineId
    {
        return $this->knownEngines[$host] ?? null;
    }

    /**
     * @param EngineId $engineId
     * @return bool
     */
    protected function isEngineTimeCached(EngineId $engineId) : bool
    {
        return array_key_exists($engineId->toBinary(), $this->engineTime);
    }

    /**
     * @param EngineId $engineId
     * @return TimeSync
     */
    protected function getEngineTime(EngineId $engineId) : TimeSync
    {
        return $this->engineTime[$engineId->toBinary()];
    }

    /**
     * @param $engineId
     */
    protected function clearCachedEngine(EngineId $engineId) : void
    {
        foreach ($this->knownEngines as $i => $knownEngine) {
            if ($knownEngine->toBinary() === $engineId->toBinary()) {
                unset($this->knownEngines[$i]);
                break;
            }
        }
        if (isset($this->engineTime[$engineId->toBinary()])) {
            unset($this->engineTime[$engineId->toBinary()]);
        }
    }

    /**
     * @param array $options
     * @return EngineId|null
     */
    protected function getEngineIdFromOptions(array $options) : ?EngineId
    {
        return ($options['engine_id'] instanceof EngineId) ? $options['engine_id'] : null;
    }

    /**
     * @param AbstractMessageV3 $messageV3
     * @return bool
     */
    protected function isTrapRequest(AbstractMessageV3 $messageV3) : bool
    {
        return ($messageV3 instanceof MessageRequestV3 && $messageV3->getRequest() instanceof TrapV2Request);
    }

    /**
     * @param AbstractMessageV3 $message
     * @param array $options
     * @return EngineId
     * @throws SecurityModelException
     */
    protected function getOutgoingEngineId(AbstractMessageV3 $message, array $options) : EngineId
    {
        $host = $options['host'] ?? '';
        $engineId = $this->getEngineIdFromOptions($options);

        if ($engineId) {
            return $engineId;
        }

        # Try to generate an EngineId for a trap request if no explicitly defined...
        if ($this->isTrapRequest($message)) {
            # This will have issues with IPv6. Anyway to support that? Seems like gethostbyname() should be fixed
            $engineId = EngineId::fromIPv4($_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname()));

            try {
                $engineId->toBinary();
            } catch (\Exception $e) {
                throw new SecurityModelException(sprintf('Unable to generate an engine ID for trap. %s', $e->getMessage()), 0, $e);
            }

            return $engineId;
        }

        # The EngineId was not explicitly defined so we try to look it up based on the host and run some quick checks...
        $engineId = $engineId ?? $this->getEngineIdForHost($host);
        if ($engineId === null) {
            throw new RuntimeException(sprintf(
                'The engine ID for %s is not known.',
                $host
            ));
        }
        if (!$this->isEngineTimeCached($engineId)) {
            throw new RuntimeException(sprintf(
                'The cached engine time was not found for %s.',
                $host
            ));
        }

        return $engineId;
    }
}
