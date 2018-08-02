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
    protected const MAX_ID = 2147483647;

    protected const USM_UNKNOWN_ENGINE_ID = '1.3.6.1.6.3.15.1.1.4.0';

    /**
     * @var PrivacyModuleFactory
     */
    protected $privacyFactory;

    /**
     * @var AuthenticationModuleFactory
     */
    protected $authFactory;

    /**
     * @param PrivacyModuleFactory|null $privacy
     * @param AuthenticationModuleFactory|null $auth
     */
    public function __construct(?PrivacyModuleFactory $privacy = null, ?AuthenticationModuleFactory $auth = null)
    {
        $this->privacyFactory = $privacy ?: new PrivacyModuleFactory();
        $this->authFactory = $auth ?: new AuthenticationModuleFactory();
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

        return $message;
    }

    /**
     * {@inheritdoc}
     */
    public function handleOutgoingMessage(AbstractMessageV3 $message, array $options) : AbstractMessageV3
    {
        $header = $message->getMessageHeader();

        $securityParams = $message->getSecurityParameters();
        if (!$securityParams) {
            $securityParams = new UsmSecurityParameters((string)$options['context_engine_id']);
            $message->setSecurityParameters($securityParams);
        }
        $header->setSecurityModel($securityParams->getSecurityModel());

        if ($header->hasPrivacy()) {
            $password = $options['priv_pwd'] ?? '';
            $this->privacyFactory->get($options['priv_mech'])->encryptData(
                $message,
                $this->authFactory->get($options['auth_mech']),
                $password
            );
        }

        $securityParams->setUsername($options['user'] ?? '');
        if ($header->hasAuthentication()) {
            $password = $options['auth_pwd'] ?? '';
            $this->authFactory->get($options['auth_mech'])->authenticateOutgoingMsg($message, $password);
        }

        return $message;
    }

    /**
     * {@inheritdoc}
     */
    public function getDiscoveryRequest(AbstractMessageV3 $messageV3, array $options): ?MessageRequestInterface
    {
        $user = $options['user'] ?? '';
        $engineId = $options['context_engine_id'] ?? '';
        $request = new MessageRequestV3(
            new MessageHeader(random_int(1, self::MAX_ID), MessageHeader::FLAG_REPORTABLE, $messageV3->getMessageHeader()->getSecurityModel()),
            new ScopedPduRequest(new GetRequest(new OidList()), $engineId),
            null,
            new UsmSecurityParameters($engineId, 0, 0, $user)
        );

        return $request;
    }

    /**
     * {@inheritdoc}
     */
    public function handleDiscoveryResponse(AbstractMessageV3 $message, MessageResponseInterface $discoveryResponse, array $options): AbstractMessageV3
    {
        $usm = $discoveryResponse->getSecurityParameters();
        $response = $discoveryResponse->getResponse();
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

        /** @var UsmSecurityParameters $securityParams */
        $message->setSecurityParameters(new UsmSecurityParameters(
            $usm->getEngineId(),
            $usm->getEngineBoots(),
            $usm->getEngineTime(),
            $options['user'] ?? ''
        ));
        $message->getScopedPdu()->setContextEngineId($usm->getEngineId());

        return $message;
    }

    /**
     * {@inheritdoc}
     */
    public static function supports() : int
    {
        return 3;
    }
}
