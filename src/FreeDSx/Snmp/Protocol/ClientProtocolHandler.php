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
use FreeDSx\Snmp\Exception\RuntimeException;
use FreeDSx\Snmp\Exception\SnmpRequestException;
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
        'context_engine_id' => '',
        'context_name' => '',
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
     * @var SecurityModelModuleFactory
     */
    protected $securityModelFactory;

    /**
     * @var int
     */
    protected $id = 0;

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
        $options = array_merge($this->options, $options);
        $id = $this->generateId();

        $this->setPduId($request, $id);
        $message = $this->getMessageRequest($request, $options);

        if ($message instanceof MessageRequestV3) {
            $response = $this->sendV3Message($message, $options);
        } else {
            $response = $this->sendRequestGetResponse($message);
        }

        if ($response) {
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
     * @return MessageResponseInterface|null
     * @throws ConnectionException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Snmp\Exception\ProtocolException
     */
    protected function sendV3Message(MessageRequestV3 $message, array $options) : ?MessageResponseInterface
    {
        $header = $message->getMessageHeader();
        $securityModule = $this->securityModelFactory->get($header->getSecurityModel());

        $discovery = $securityModule->getDiscoveryRequest($message, $options);
        if ($discovery) {
            $response = $this->sendRequestGetResponse($discovery);
            $securityModule->handleDiscoveryResponse($message, $response, $options);
        }
        $message = $securityModule->handleOutgoingMessage($message, $options);

        $response = $this->sendRequestGetResponse($message);
        if ($response) {
            $response = $securityModule->handleIncomingMessage($response, $options);
        }

        return $response;
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
            return new MessageRequestV3(
                $this->generateMessageHeader($options),
                new ScopedPduRequest($request, $options['context_engine_id'], $options['context_name'])
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
     * @param array $options
     * @return MessageHeader
     * @throws \Exception
     */
    protected function generateMessageHeader(array $options) : MessageHeader
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
        $header->addFlag(MessageHeader::FLAG_REPORTABLE);

        return $header;
    }

    /**
     * @param MessageResponseInterface $message
     * @param int $expectedId
     * @throws SnmpRequestException
     */
    protected function validateResponse(MessageResponseInterface $message, int $expectedId) : void
    {
        $response = $message->getResponse();

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
