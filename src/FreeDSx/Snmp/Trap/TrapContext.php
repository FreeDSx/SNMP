<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Trap;

use FreeDSx\Snmp\Message\AbstractMessage;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;

/**
 * Represents the context of the incoming trap request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TrapContext
{
    /**
     * @var string
     */
    protected $ipAddress;

    /**
     * @var int
     */
    protected $version;

    /**
     * @var MessageRequestInterface
     */
    protected $message;

    /**
     * @param string $ipAddress
     * @param int $version
     * @param MessageRequestInterface $message
     */
    public function __construct(string $ipAddress, int $version, MessageRequestInterface $message)
    {
        $this->ipAddress = $ipAddress;
        $this->version = $version;
        $this->message = $message;
    }

    /**
     * @return MessageRequestInterface|AbstractMessage|AbstractMessageV3
     */
    public function getMessage() : MessageRequestInterface
    {
        return $this->message;
    }

    /**
     * Get the IP address that sent the trap.
     *
     * @return string
     */
    public function getIpAddress() : string
    {
        return $this->ipAddress;
    }

    /**
     * @return InformRequest|TrapV1Request|TrapV2Request
     */
    public function getTrap() : RequestInterface
    {
        return $this->message->getRequest();
    }

    /**
     * Get the SNMP version for the incoming trap.
     *
     * @return int
     */
    public function getVersion() : int
    {
        return $this->version;
    }

    /**
     * @return bool
     */
    public function isTrapV1() : bool
    {
        return ($this->message->getRequest() instanceof TrapV1Request);
    }

    /**
     * @return bool
     */
    public function isTrapV2() : bool
    {
        return ($this->message->getRequest() instanceof TrapV2Request);
    }

    /**
     * @return bool
     */
    public function isInformRequest() : bool
    {
        return ($this->message->getRequest() instanceof InformRequest);
    }
}
