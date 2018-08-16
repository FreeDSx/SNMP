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
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\Factory\AuthenticationModuleFactory;
use FreeDSx\Snmp\Protocol\Factory\PrivacyModuleFactory;
use FreeDSx\Snmp\Protocol\IdGeneratorTrait;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetRequest;
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
     * @var string[]
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

        if ($securityParams && $header->hasPrivacy()) {
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
        $host = $options['host'] ?? '';
        $engineId = $options['context_engine_id'] ?? $this->getEngineIdForHost($host);
        if ((string) $engineId === '') {
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

        $header = $message->getMessageHeader();
        $user = $options['user'] ?? '';
        $cachedTime = $this->getEngineTime($engineId);
        $usm = new UsmSecurityParameters(
            $engineId,
            $cachedTime->getEngineBoot(),
            $cachedTime->getEngineTime(),
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

        $engineId = $options['context_engine_id'] ?? '';
        if ($usm instanceof UsmSecurityParameters && $usm->getEngineId() !== '') {
            $engineId = $usm->getEngineId();
        }
        if ($engineId === '' && array_key_exists($host, $this->knownEngines)) {
            $engineId = $this->knownEngines[$host];
        }

        # Not a known engineId, either for this host or otherwise. No engineId specifically used. Discovery needed...
        if ($engineId === '') {
            return true;
        }

        # Time was never cached for the engine, so discovery is required...
        if (!$this->isEngineTimeCached($engineId)) {
            return true;
        }
        $time = $this->engineTime[$engineId];

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
        $engineId = $options['context_engine_id'] ?? '';

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
        if (!($usm instanceof UsmSecurityParameters && (string) $usm->getEngineId() !== '')) {
            throw new SnmpRequestException($discoveryResponse, 'Failed to discover the engine id for USM.');
        }
        if (!$response instanceof ReportResponse) {
            throw new SnmpRequestException($discoveryResponse, sprintf(
                'Failed to discover the engine id for USM. Expected a report response, got %s',
                get_class($response)
            ));
        }
        if (!$response->getOids()->has(self::USM_UNKNOWN_ENGINE_ID)) {
            throw new SnmpRequestException($discoveryResponse, 'Expected an usmStatsUnknownEngineIDs OID, but none was received.');
        }
        $this->knownEngines[$host] = $usm->getEngineId();
        $this->engineTime[$usm->getEngineId()] = new TimeSync($usm->getEngineBoots(), $usm->getEngineTime());

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
     * @throws RediscoveryNeededException
     * @throws SnmpRequestException
     */
    protected function validateIncomingResponse(MessageResponseInterface $response, array $options) : void
    {
        if (!$response->getResponse() instanceof ReportResponse) {
            return;
        }
        /** @var UsmSecurityParameters $secParams */
        $secParams = $response->getSecurityParameters();

        if ($secParams->getEngineId() !== $this->knownEngines[$options['host']]) {
            throw new SnmpRequestException(
                $response,
                'The expected engine ID does not match the known engine ID for this host.'
            );
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
                if (in_array($oid->getOid(), self::ERROR_MAP_CLEAR_TIME) && isset($this->engineTime[$secParams->getEngineId()])) {
                    unset($this->engineTime[$secParams->getEngineId()]);
                }
                throw new SnmpRequestException($response, self::ERROR_MAP_USM[$oid->getOid()]);
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
     * @return null|string
     */
    protected function getEngineIdForHost(string $host)
    {
        return $this->knownEngines[$host] ?? null;
    }

    /**
     * @param string $engineId
     * @return bool
     */
    protected function isEngineTimeCached(string $engineId) : bool
    {
        return array_key_exists($engineId, $this->engineTime);
    }

    /**
     * @param string $engineId
     * @return TimeSync
     */
    protected function getEngineTime(string $engineId) : TimeSync
    {
        return $this->engineTime[$engineId];
    }
}
