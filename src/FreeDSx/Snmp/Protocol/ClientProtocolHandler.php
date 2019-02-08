<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Protocol;

use FreeDSx\Snmp\Exception\ConnectionException;
use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Exception\RediscoveryNeededException;
use FreeDSx\Snmp\Exception\RuntimeException;
use FreeDSx\Snmp\Exception\SecurityModelException;
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Module\SecurityModel\SecurityModelModuleInterface;
use FreeDSx\Snmp\Protocol\Factory\SecurityModelModuleFactory;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Request\MessageRequestV1;
use FreeDSx\Snmp\Message\Request\MessageRequestV2;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Response\ReportResponse;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Socket;

/**
 * Handles SNMP client protocol logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandler
{
    use ProtocolTrait;

    /**
     * @var array
     */
    protected $options = [
        'transport' => 'udp',
        'use_tls' => false,
        'ssl_validate_cert' => true,
        'ssl_allow_self_signed' => null,
        'ssl_ca_cert' => null,
        'ssl_peer_name' => null,
        'port' => 161,
        'host' => 'localhost',
        'user' => null,
        'community' => 'public',
        'udp_retry' => 5,
        'timeout_connect' => 5,
        'timeout_read' => 10,
        'version' => 2,
        'security_model' => 'usm',
        'engine_id' => null,
        'context_name' => null,
        'use_auth' => false,
        'use_priv' => false,
        'auth_mech' => null,
        'priv_mech' => null,
        'priv_pwd' => null,
        'auth_pwd' => null,
        'id_min' => null,
        'id_max' => null,
    ];

    /**
     * @var array
     */
    protected $securityModel = [
        'usm' => 3,
    ];

    /**
     * @param array $options
     * @param null|Socket $socket
     * @param null|SnmpEncoder $encoder
     * @param null|Asn1MessageQueue $queue
     * @param SecurityModelModuleFactory|null $securityModelFactory
     */
    public function __construct(array $options, ?Socket $socket = null, ?SnmpEncoder $encoder = null, ?Asn1MessageQueue $queue = null, ?SecurityModelModuleFactory $securityModelFactory = null)
    {
        $this->socket = $socket;
        $this->encoder = $encoder;
        $this->options = $options;
        $this->queue = $queue;
        $this->securityModelFactory = $securityModelFactory ?: new SecurityModelModuleFactory();
    }

    /**
     * Handles client protocol logic for an SNMP request to get a potential response.
     *
     * @param RequestInterface $request
     * @param array $options
     * @return MessageResponseInterface
     * @throws ConnectionException
     * @throws \Exception
     */
    public function handle(RequestInterface $request, array $options) : ?MessageResponseInterface
    {
        $options = \array_merge($this->options, $options);
        $message = $this->getMessageRequest($request, $options);

        if (!\in_array($request->getPduTag(), $this->allowedRequests[$message->getVersion()])) {
            throw new InvalidArgumentException(sprintf(
                'The request type "%s" is not allowed in SNMP version %s.',
                get_class($request),
                $this->versionMap[$message->getVersion()]
            ));
        }

        if ($message instanceof MessageRequestV3) {
            $response = $this->sendV3Message($message, $options);
        } else {
            $id = $this->generateId();
            $this->setPduId($request, $id);
            $response = $this->sendRequestGetResponse($message);
            $this->validateResponse($response, $id);
        }

        return $response;
    }

    /**
     * @param MessageRequestInterface $message
     * @return MessageResponseInterface|null
     * @throws ConnectionException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     */
    protected function sendRequestGetResponse(MessageRequestInterface $message) : ?MessageResponseInterface
    {
        try {
            $this->socket()->write($this->encoder()->encode($message->toAsn1()));
        } catch (\FreeDSx\Socket\Exception\ConnectionException $e) {
            throw new ConnectionException('Unable to send message to host.', $e->getCode(), $e);
        }

        # No responses expected from traps...
        if ($message->getRequest() instanceof TrapV1Request || $message->getRequest() instanceof TrapV2Request) {
            return null;
        }

        try {
            return $this->queue()->getMessage();
        } catch (\FreeDSx\Socket\Exception\ConnectionException $e) {
            throw new ConnectionException('No message received from host.', $e->getCode(), $e);
        }
    }

    /**
     * @param MessageRequestV3 $message
     * @param array $options
     * @param bool $forcedDiscovery
     * @return MessageResponseInterface|null
     * @throws ConnectionException
     * @throws SnmpRequestException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Snmp\Exception\ProtocolException
     * @throws SecurityModelException
     */
    protected function sendV3Message(MessageRequestV3 $message, array $options, bool $forcedDiscovery = false) : ?MessageResponseInterface
    {
        $response = null;
        $header = $message->getMessageHeader();
        $securityModule = $this->securityModelFactory->get($header->getSecurityModel());

        try {
            if ($forcedDiscovery || $securityModule->isDiscoveryRequestNeeded($message, $options)) {
                $this->performDiscovery($message, $securityModule, $options);
            }

            $id = $this->generateId();
            $this->setPduId($message->getRequest(), $id);
            $message = $securityModule->handleOutgoingMessage($message, $options);
            $response = $this->sendRequestGetResponse($message);

            if ($response) {
                $response = $securityModule->handleIncomingMessage($response, $options);
                $this->validateResponse($response, $id);
            }

            return $response;
        } catch (RediscoveryNeededException $e) {
            if (!$forcedDiscovery) {
                return $this->sendV3Message($message, $options, true);
            }
            throw new SnmpRequestException($response, $e->getMessage(), $e);
        } catch (SecurityModelException $e) {
            throw new SnmpRequestException($response, $e->getMessage(), $e);
        }
    }

    /**
     * @param MessageRequestV3 $message
     * @param $securityModule
     * @param array $options
     * @throws ConnectionException
     * @throws SnmpRequestException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     */
    protected function performDiscovery(MessageRequestV3 $message, SecurityModelModuleInterface $securityModule, array $options) : void
    {
        $discovery = $securityModule->getDiscoveryRequest($message, $options);
        $id = $this->generateId();
        $this->setPduId($discovery->getRequest(), $id);
        $response = $this->sendRequestGetResponse($discovery);
        $this->validateResponse($response, $id, false);
        $securityModule->handleDiscoveryResponse($message, $response, $options);
    }

    /**
     * @param RequestInterface $request
     * @param array $options
     * @return MessageRequestInterface
     * @throws \Exception
     */
    protected function getMessageRequest(RequestInterface $request, array $options) : MessageRequestInterface
    {
        if ($options['version'] === 1) {
            return new MessageRequestV1($options['community'], $request);
        } elseif ($options['version'] === 2) {
            return new MessageRequestV2($options['community'], $request);
        } elseif ($options['version'] === 3) {
            $engineId = ($options['engine_id'] instanceof EngineId) ? $options['engine_id'] : null;
            return new MessageRequestV3(
                $this->generateMessageHeader($request, $options),
                new ScopedPduRequest($request, $engineId, (string) $options['context_name'])
            );
        } else {
            throw new RuntimeException(sprintf('SNMP version %s is not supported', $options['version']));
        }
    }

    /**
     * Needed to set the ID in the PDU. Unfortunately the protocol designers put the ID for the overall message inside
     * of the PDU (essentially the request / response objects). This made it awkward to work with when separating the
     * logic of the ID generation /message creation. Maybe a better way to handle this in general?
     *
     * @param RequestInterface $request
     * @param int $id
     */
    protected function setPduId(RequestInterface $request, int $id)
    {
        # The Trap v1 PDU has no request ID associated with it.
        if ($request instanceof  TrapV1Request) {
            return;
        }
        $requestObject = new \ReflectionObject($request);
        $idProperty = $requestObject->getProperty('id');
        $idProperty->setAccessible(true);
        $idProperty->setValue($request, $id);
    }

    /**
     * @param RequestInterface $request
     * @param array $options
     * @return MessageHeader
     * @throws \Exception
     */
    protected function generateMessageHeader(RequestInterface $request, array $options) : MessageHeader
    {
        $header = new MessageHeader($this->generateId(0));

        if ($options['use_auth'] || $options['use_priv']) {
            if (!isset($this->securityModel[$options['security_model']])) {
                throw new InvalidArgumentException(sprintf(
                    'The security model %s is not recognized.',
                    $options['security_model']
                ));
            }
            $header->setSecurityModel($this->securityModel[$options['security_model']]);
        }
        if ($options['use_auth']) {
            $header->addFlag(MessageHeader::FLAG_AUTH);
        }
        if ($options['use_priv']) {
            $header->addFlag(MessageHeader::FLAG_PRIV);
        }
        # Unconfirmed PDUs do not have the reportable flag set
        if (!$request instanceof TrapV2Request) {
            $header->addFlag(MessageHeader::FLAG_REPORTABLE);
        }

        return $header;
    }

    /**
     * @param null|MessageResponseInterface $message
     * @param int $expectedId
     * @param  bool $throwOnReport
     * @throws SnmpRequestException
     */
    protected function validateResponse(?MessageResponseInterface $message, int $expectedId, bool $throwOnReport = true) : void
    {
        if (!$message) {
            return;
        }
        $response = $message->getResponse();
        if (!\in_array($response->getPduTag(), $this->allowedResponses[$message->getVersion()])) {
            throw new SnmpRequestException($message, sprintf(
                'The PDU type received (%s) is not allowed in SNMP version %s.',
                get_class($response),
                $this->versionMap[$message->getVersion()]
            ));
        }
        if ($throwOnReport && $response instanceof ReportResponse) {
            $oids = [];
            foreach ($response->getOids() as $oid) {
                $oids[] = $oid->getOid();
            }
            throw new SnmpRequestException($message, sprintf(
                'Received a report PDU with the OID(s): %s',
                implode(', ', $oids)
            ));
        }
        if ($response->getId() !== $expectedId) {
            throw new SnmpRequestException($message, sprintf(
                'Unexpected message ID received. Expected %s but got %s.',
                $expectedId,
                $response->getId()
            ));
        }
        if ($response->getErrorStatus() !== 0) {
            throw new SnmpRequestException($message);
        }
    }
}
