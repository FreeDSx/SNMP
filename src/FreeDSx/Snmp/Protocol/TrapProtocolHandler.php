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

use FreeDSx\Snmp\Message\AbstractMessage;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\Request\MessageRequest;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseV2;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Protocol\Factory\SecurityModelModuleFactory;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Response\Response;
use FreeDSx\Snmp\Trap\TrapContext;
use FreeDSx\Snmp\Trap\TrapListenerInterface;
use FreeDSx\Snmp\Module\SecurityModel\Usm\UsmUser;
use FreeDSx\Socket\Socket;

/**
 * Handles the logic associated with building the trap request and sending it to the listener.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TrapProtocolHandler
{
    use ProtocolTrait;

    private const DEFAULT_OPTIONS = [
        'timeout_connect' => 5,
        'timeout_read' => 10,
        'ssl_validate_cert' => true,
        'ssl_allow_self_signed' => null,
        'ssl_ca_cert' => null,
        'ssl_peer_name' => null,
        'whitelist' => null,
        'version' => null,
        'community' => null,
        'engine_id' => null,
    ];

    /**
     * @var TrapListenerInterface
     */
    protected $listener;

    /**
     * @param TrapListenerInterface $listener
     * @param array $options
     * @param SnmpEncoder|null $encoder
     * @param Socket|null $socket
     * @param SecurityModelModuleFactory|null $securityModelFactory
     */
    public function __construct(TrapListenerInterface $listener, array $options, ?SnmpEncoder $encoder = null, ?Socket $socket = null, ?SecurityModelModuleFactory $securityModelFactory = null)
    {
        $this->listener = $listener;
        $this->options = $options + self::DEFAULT_OPTIONS;
        $this->encoder = $encoder;
        $this->socket = $socket;
        $this->securityModelFactory = $securityModelFactory ?: new SecurityModelModuleFactory();
    }

    /**
     * @param string $ipAddress
     * @param string $data
     * @param array $options
     */
    public function handle(string $ipAddress, $data, array $options) : void
    {
        $options = \array_merge($this->options, $options);

        $port = (int) \substr($ipAddress, \strrpos($ipAddress, ':'));
        # IPv6 should be enclosed in brackets, though PHP doesn't represent it that way from a socket.
        # Adding the trim in case that changes at some point.
        $ipAddress = \trim(\substr($ipAddress, 0, \strrpos($ipAddress, ':')), '[]');

        if (!$this->isIpAddressAllowed($ipAddress, $options)) {
            return;
        }
        $message = $this->getMessage($data);
        if ($message && !$this->isVersionAllowed($message->getVersion(), $options)) {
            return;
        }
        if ($message instanceof MessageRequestV3) {
            $message = $this->handleV3Trap($message, $ipAddress, $options);
        }
        # If an error happened during SNMPv3 processing, then the message will return null
        if ($message === null) {
            return;
        }
        if (!$this->isMessageAllowed($message, $options)) {
            return;
        }
        $version = $this->versionMap[$message->getVersion()];
        $context = new TrapContext($ipAddress, $version, $message);
        $this->listener->receive($context);

        if ($message->getRequest() instanceof InformRequest) {
            $this->sendResponse($ipAddress, $port, $message);
        }
    }

    /**
     * @param string $ip
     * @param int $port
     * @param MessageRequestInterface $message
     * @todo Configurable retry logic? Would hold up traps though if we are synchronous
     */
    protected function sendResponse(string $ip, int $port, MessageRequestInterface $message) : void
    {
        /** @var InformRequest $request */
        $request = $message->getRequest();
        $response = new Response(
            $request->getId(),
            $request->getErrorStatus(),
            $request->getErrorIndex(),
            $request->getOids()
        );
        $informResponse = new MessageResponseV2($message->getCommunity(), $response);

        try {
            $this->socket(['host' => $ip, 'port' => $port])->write($this->encoder()->encode($informResponse->toAsn1()));
            $this->socket()->close();
            $this->socket = null;
        } catch (\Exception $e) {
            return;
        }
    }

    /**
     * @param string $ip
     * @param array $options
     * @return bool
     */
    protected function isIpAddressAllowed(string $ip, array $options) : bool
    {
        if ($options['whitelist'] !== null && is_array($options['whitelist'])) {
            return \in_array($ip, $options['whitelist'], true);
        } else {
            return $this->listener->accept($ip);
        }
    }

    /**
     * @param MessageRequestInterface|null $message
     * @param array $options
     * @return bool
     */
    protected function isMessageAllowed(?MessageRequestInterface $message, array $options) : bool
    {
        if (!$message) {
            return false;
        }
        $version = $message->getVersion();
        $request = $message->getRequest();
        # Only allow trap type PDUs...
        if (!($request instanceof TrapV1Request || $request instanceof TrapV2Request || $request instanceof InformRequest)) {
            return false;
        }

        # Verify that the request type is valid for the given SNMP version...
        if (!$this->isRequestAllowed($version, $request->getPduTag())) {
            return false;
        }

        # If we received an SNMP v1/v2 message, and it was defined to only accept a specific community...
        if (($version === 0 || $version === 1) && $options['community'] !== null) {
            return $message->getCommunity() === $options['community'];
        }

        return true;
    }

    /**
     * @param mixed $data
     * @return MessageRequestInterface|AbstractMessage|AbstractMessageV3|null
     */
    protected function getMessage($data) : ?MessageRequestInterface
    {
        try {
            return MessageRequest::fromAsn1($this->encoder()->decode($data));
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * @param MessageRequestV3 $message
     * @param string $ipAddress
     * @param array $options
     * @return null|MessageRequestV3
     */
    protected function handleV3Trap(MessageRequestV3 $message, string $ipAddress, array $options) : ?MessageRequestV3
    {
        $header = $message->getMessageHeader();
        $secParams = $message->getSecurityParameters();

        try {
            $securityModule = $this->securityModelFactory->get($header->getSecurityModel());
            # Only supporting USM currently
            if (!$secParams instanceof UsmSecurityParameters) {
                return null;
            }
            $usmUser = $this->listener->getUsmUser($secParams->getEngineId(), $ipAddress, $secParams->getUsername());
            if ($usmUser === null || !$this->isUsmUserValid($usmUser)) {
                return null;
            }
            $options = $this->mergeOptionsFromUser($usmUser, $options);
            $message = $securityModule->handleIncomingMessage($message, $options);

            # @todo Currently unsupported. Lots of work needed to support an inform request in v3.
            if (!$message->getScopedPdu() || $message->getScopedPdu()->getRequest() instanceof InformRequest) {
                return null;
            }

            return $message;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * @param UsmUser $user
     * @param array $options
     * @return array
     */
    protected function mergeOptionsFromUser(UsmUser $user, array $options) : array
    {
        $options['user'] = $user->getUser();
        $options['use_auth'] = $user->getUseAuth();
        $options['use_priv'] = $user->getUsePriv();
        $options['auth_mech'] = $user->getAuthMech();
        $options['auth_pwd'] = $user->getAuthPassword();
        $options['priv_mech'] = $user->getPrivMech();
        $options['priv_pwd'] = $user->getPrivPassword();

        return $options;
    }

    /**
     * @param UsmUser $user
     * @return bool
     */
    protected function isUsmUserValid(UsmUser $user) : bool
    {
        if ($user->getUsePriv() && !$user->getUseAuth()) {
            return false;
        }
        if ($user->getUseAuth() && ($user->getAuthPassword() === null || $user->getAuthMech() === null)) {
            return false;
        }
        if ($user->getUsePriv() && ($user->getPrivPassword() === null || $user->getPrivMech() === null)) {
            return false;
        }

        return true;
    }

    /**
     * @param int $version
     * @param array $options
     * @return bool
     */
    protected function isVersionAllowed(int $version, array $options) : bool
    {
        if ($options['version'] !== null) {
            return ($this->versionMap[$version] === $options['version']);
        }

        return true;
    }
}
