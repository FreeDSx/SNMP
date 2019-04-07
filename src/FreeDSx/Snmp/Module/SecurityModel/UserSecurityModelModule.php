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

use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Exception\RediscoveryNeededException;
use FreeDSx\Snmp\Exception\SecurityModelException;
use FreeDSx\Snmp\Exception\SnmpAuthenticationException;
use FreeDSx\Snmp\Exception\SnmpEncryptionException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\SecurityModel\Usm\TimeSync;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\Factory\AuthenticationModuleFactory;
use FreeDSx\Snmp\Protocol\Factory\PrivacyModuleFactory;
use FreeDSx\Snmp\Protocol\IdGeneratorTrait;
use FreeDSx\Snmp\Request\GetRequest;
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
     * @var EngineId
     */
    protected $engineId;

    /**
     * @var TimeSync
     */
    protected $localEngineTime;

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

        if (!$securityParams) {
            throw new SecurityModelException('The received SNMP message is missing the security parameters.');
        }

        $useAuth = $options['use_auth'];
        $usePriv = $options['use_priv'];
        if (!is_bool($useAuth) || !is_bool($usePriv)) {
            throw new InvalidArgumentException('Options use_auth and use_priv must have boolean value.');
        }

        if ($useAuth && !$header->hasAuthentication()) {
            throw new SecurityModelException('Authentication was requested, but the received header has none specified.');
        }
        if ($usePriv && !$header->hasPrivacy()) {
            throw new SecurityModelException('Privacy was requested, but the received header has none specified.');
        }

        if ($useAuth) {
            try {
                $message = $this->authFactory->get($options['auth_mech'])->authenticateIncomingMsg(
                    $message,
                    $options['auth_pwd']
                );
            } catch (SnmpAuthenticationException $e) {
                throw new SecurityModelException($e->getMessage());
            }
        }
        if ($usePriv) {
            try {
                $message = $this->privacyFactory->get($options['priv_mech'])->decryptData(
                    $message,
                    $this->authFactory->get($options['auth_mech']),
                    $options['priv_pwd']
                );
            } catch (SnmpEncryptionException $e) {
                throw new SecurityModelException($e->getMessage());
            }
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

        $this->setupOutgoingMessage($message, $usm);
        if ($header->hasPrivacy()) {
            $password = $options['priv_pwd'] ?? '';
            try {
                $message = $this->privacyFactory->get($options['priv_mech'])->encryptData(
                    $message,
                    $this->authFactory->get($options['auth_mech']),
                    $password
                );
            } catch (SnmpEncryptionException $e) {
                throw new SecurityModelException($e->getMessage(), $e->getCode(), $e);
            }
        }

        if ($header->hasAuthentication()) {
            $password = $options['auth_pwd'] ?? '';
            try {
                $message = $this->authFactory->get($options['auth_mech'])->authenticateOutgoingMsg($message, $password);
            } catch (SnmpAuthenticationException $e) {
                throw new SecurityModelException($e->getMessage(), $e->getCode(), $e);
            }
        }

        return $message;
    }

    /**
     * @param AbstractMessageV3 $messageV3
     * @param array $options
     * @return bool
     */
    public function isDiscoveryRequestNeeded(AbstractMessageV3 $messageV3, array $options) : bool
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
    public function isDiscoveryResponseNeeded(AbstractMessageV3 $messageV3, array $options) : bool
    {
        if (!$messageV3 instanceof MessageRequestInterface) {
            return false;
        }

        return ($this->isDiscoveryRequest($messageV3) || $this->isTimeSynchronizationRequest($messageV3, $options));
    }

    /**
     * {@inheritdoc}
     */
    public function getDiscoveryResponse(AbstractMessageV3 $messageV3, array $options) : MessageResponseInterface
    {
        $flags = MessageHeader::FLAG_NO_AUTH_NO_PRIV;
        if ($messageV3->getMessageHeader()->hasAuthentication()) {
            $flags |= MessageHeader::FLAG_AUTH;
        }

        return new MessageResponseV3(
            new MessageHeader($messageV3->getMessageHeader()->getId(), $flags),
            new ScopedPduResponse(
                new ReportResponse(
                    $messageV3->getRequest()->getId(),
                    0,
                    0,
                    new OidList(Oid::fromCounter(self::USM_UNKNOWN_ENGINE_ID, 1))
                ),
                $this->getAuthoritativeEngineId($options),
                $messageV3->getScopedPdu()->getContextName()
            ),
            null,
            new UsmSecurityParameters(
                $this->getAuthoritativeEngineId($options),
                $this->localEngineTime->getEngineBoot(),
                $this->localEngineTime->getEngineTime(),
                $messageV3->getSecurityParameters()->getUsername()
            )
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
        $this->updateCachedTime($usm);

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
        /** @var UsmSecurityParameters $secParams */
        $secParams = $response->getSecurityParameters();
        $knownEngine = $this->getEngineIdForHost($options['host']);

        if ($knownEngine === null || $secParams->getEngineId()->toBinary() !== $knownEngine->toBinary()) {
            throw new SecurityModelException('The expected engine ID does not match the known engine ID for this host.');
        }
        # Section 3.2, Step 7.b.2
        #    If the message is considered to be outside of the Time
        #    Window then an error indication (notInTimeWindow) is
        #    returned to the calling module.
        if ($this->isOutsideTimeWindow($secParams)) {
            throw new SecurityModelException('The received message is outside of the time window.');
        }
        # Section 3.2, Step 7.b.1
        if ($this->shouldUpdateCachedTime($secParams)) {
            $this->updateCachedTime($secParams);
        }
        # The rest of the checks relate specifically to report responses...
        if (!$response->getResponse() instanceof ReportResponse) {
            return;
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
                if (in_array($oid->getOid(), self::ERROR_MAP_CLEAR_TIME, true) && $this->isEngineTimeCached($secParams->getEngineId())) {
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
     * @param MessageRequestInterface $message
     * @param array $options
     * @throws SecurityModelException
     */
    protected function validateIncomingRequest(MessageRequestInterface $message, array $options) : void
    {
        /** @var UsmSecurityParameters $usm */
        $usm = $message->getSecurityParameters();
        $engineId = $this->getAuthoritativeEngineId($options);

        if ($message->getMessageHeaders()->hasPrivacy() && $message->getEncryptedPdu() === null) {
            throw new SecurityModelException('The header has privacy marked but the encrypted PDU was not set.');
        }
        if ($this->isDiscoveryRequest($message) || $this->isTimeSynchronizationRequest($message, $options)) {
            return;
        }
        if ($this->isOutsideAuthoritativeTimeWindow($usm)) {
            throw new SecurityModelException('The received message is outside of the time window.');
        }
        if ($usm->getEngineId()->toBinary() !== $engineId->toBinary()) {
            throw new SecurityModelException('The engineID is incorrect.');
        }
    }

    /**
     * @param MessageRequestInterface $message
     * @return bool
     */
    protected function isDiscoveryRequest(MessageRequestInterface $message) : bool
    {
        /** @var UsmSecurityParameters $usm */
        $usm = $message->getSecurityParameters();
        $request = $message->getRequest();

        if ($usm->getEngineId() !== null) {
            return false;
        }
        if (!($request instanceof GetRequest && $request->getOids()->count() === 0)) {
            return false;
        }

        return ($usm->getEngineBoots() === 0 && $usm->getEngineTime() === 0);
    }

    /**
     * @param MessageRequestInterface $message
     * @param array $options
     * @return bool
     * @throws SecurityModelException
     */
    protected function isTimeSynchronizationRequest(MessageRequestInterface $message, array $options) : bool
    {
        /** @var UsmSecurityParameters $usm */
        $usm = $message->getSecurityParameters();
        $request = $message->getRequest();
        $engineId = $this->getAuthoritativeEngineId($options);
        /** @var MessageHeader $header */
        $header = $message->getMessageHeader();

        if (!($usm->getEngineId() && $usm->getEngineId()->toBinary() === $engineId->toBinary())) {
            return false;
        }
        if (!($request instanceof GetRequest && $request->getOids()->count() === 0)) {
            return false;
        }
        if (!($header->hasAuthentication() && $header->isReportable())) {
            return false;
        }

        return ($usm->getEngineBoots() === 0 && $usm->getEngineTime() === 0);
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
     * @param UsmSecurityParameters $secParams
     */
    protected function updateCachedTime(UsmSecurityParameters $secParams) : void
    {
        $this->engineTime[$secParams->getEngineId()->toBinary()] = new TimeSync(
            $secParams->getEngineBoots(),
            $secParams->getEngineTime()
        );
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

        # Try to generate an EngineId for a trap request if none is explicitly defined...
        if ($this->isTrapRequest($message)) {
            return $this->generateIPv4EngineId();
        }

        # The EngineId was not explicitly defined so we try to look it up based on the host and run some quick checks...
        $engineId = $engineId ?? $this->getEngineIdForHost($host);
        if ($engineId === null) {
            throw new SecurityModelException(sprintf(
                'The engine ID for %s is not known.',
                $host
            ));
        }
        if (!$this->isEngineTimeCached($engineId)) {
            throw new SecurityModelException(sprintf(
                'The cached engine time was not found for %s.',
                $host
            ));
        }

        return $engineId;
    }

    /**
     * @param UsmSecurityParameters $secParams
     * @return bool
     */
    protected function isOutsideTimeWindow(UsmSecurityParameters $secParams) : bool
    {
        if (!$this->isEngineTimeCached($secParams->getEngineId())) {
            return false;
        }
        $timeSync = $this->getEngineTime($secParams->getEngineId());

        # Section 3.2, Step 7.b.2
        #   the value of the msgAuthoritativeEngineBoots field is
        #   less than the local notion of the value of
        #   snmpEngineBoots;
        if ($secParams->getEngineBoots() < $timeSync->getEngineBoot()) {
            return true;
        }

        # Section 3.2, Step 7.b.2
        #    the value of the msgAuthoritativeEngineBoots field is
        #    equal to the local notion of the value of snmpEngineBoots
        #    and the value of the msgAuthoritativeEngineTime field is
        #    more than 150 seconds less than the local notion of the
        #    value of snmpEngineTime.
        if ($secParams->getEngineBoots() === $timeSync->getEngineBoot() && (($timeSync->getEngineTime() - $secParams->getEngineTime()) > 150)) {
            return true;
        }

        return false;
    }

    /**
     * Section 3.2, Step 7
     *    If the message is considered to be outside of the Time Window
     *    then the usmStatsNotInTimeWindows counter is incremented and
     *    an error indication (notInTimeWindow) together with the OID,
     *    the value of the incremented counter, and an indication that
     *    the error must be reported with a securityLevel of authNoPriv,
     *    is returned to the calling module
     *
     * @param UsmSecurityParameters $secParams
     * @return bool
     */
    protected function isOutsideAuthoritativeTimeWindow(UsmSecurityParameters $secParams) : bool
    {
        # Section 3.2, Step 7.a
        #    the value of the msgAuthoritativeEngineBoots field differs
        #    from the local value of snmpEngineBoots;
        if ($secParams->getEngineBoots() !== $this->localEngineTime->getEngineBoot()) {
            return true;
        }
        # Section 3.2, Step 7.a
        #    the value of the msgAuthoritativeEngineTime field differs
        #    from the local notion of snmpEngineTime by more than +/- 150
        #    seconds.
        if (\abs($this->localEngineTime->getEngineTime() - $secParams->getEngineTime()) > 150) {
            return true;
        }

        return false;
    }

    /**
     * @param UsmSecurityParameters $secParams
     * @return bool
     */
    protected function shouldUpdateCachedTime(UsmSecurityParameters $secParams) : bool
    {
        if (!$this->isEngineTimeCached($secParams->getEngineId())) {
            return true;
        }
        $timeSync = $this->getEngineTime($secParams->getEngineId());

        # Section 3.2, Step 7.b.1
        #    the extracted value of the msgAuthoritativeEngineBoots
        #    field is greater than the local notion of the value of
        #    snmpEngineBoots;
        if ($secParams->getEngineBoots() > $timeSync->getEngineBoot()) {
            return true;
        }
        # Section 3.2, Step 7.b.1
        #    the extracted value of the msgAuthoritativeEngineBoots
        #    field is equal to the local notion of the value of
        #    snmpEngineBoots, and the extracted value of
        #    msgAuthoritativeEngineTime field is greater than the
        #    value of latestReceivedEngineTime,
        if ($secParams->getEngineBoots() === $timeSync->getEngineBoot() && $secParams->getEngineTime() > $timeSync->getEngineTime()) {
            return true;
        }

        return false;
    }

    /**
     * @param AbstractMessageV3 $message
     * @param UsmSecurityParameters $secParams
     */
    protected function setupOutgoingMessage(AbstractMessageV3 $message, UsmSecurityParameters $secParams) : void
    {
        $msgObject = new \ReflectionObject($message);
        $scopedPduObject = new \ReflectionObject($message->getScopedPdu());

        $secParamsProperty = $msgObject->getProperty('securityParams');
        $secParamsProperty->setAccessible(true);
        $secParamsProperty->setValue($message, $secParams);

        $encryptedProperty = $msgObject->getProperty('encryptedPdu');
        $encryptedProperty->setAccessible(true);
        $encryptedProperty->setValue($message, null);

        $contextEngineIdProperty = $scopedPduObject->getProperty('contextEngineId');
        $contextEngineIdProperty->setAccessible(true);
        $contextEngineIdProperty->setValue($message, $secParams->getEngineId());
    }

    /**
     * @return EngineId
     * @throws SecurityModelException
     */
    protected function generateIPv4EngineId() : EngineId
    {
        # This will have issues with IPv6. Anyway to support that? Seems like gethostbyname() should be fixed
        $engineId = EngineId::fromIPv4($_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname()));

        try {
            $engineId->toBinary();
        } catch (\Exception $e) {
            throw new SecurityModelException(sprintf('Unable to generate an engine ID for trap. %s', $e->getMessage()), 0, $e);
        }

        return $engineId;
    }

    /**
     * @param array $options
     * @return EngineId
     * @throws SecurityModelException
     */
    protected function getAuthoritativeEngineId(array $options) : EngineId
    {
        if ($this->engineId) {
            return $this->engineId;
        }

        $this->engineId = $this->getEngineIdFromOptions($options);
        if (!$this->engineId) {
            $this->generateIPv4EngineId();
        }

        return $this->engineId;
    }
}
