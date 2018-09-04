<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp;

use FreeDSx\Snmp\Exception\ConnectionException;
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Protocol\ClientProtocolHandler;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Value\TimeTicksValue;
use FreeDSx\Socket\Socket;

/**
 * The SnmpClient class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SnmpClient
{
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
    ];

    /**
     * @var Socket
     */
    protected $socket;

    /**
     * @var ClientProtocolHandler
     */
    protected $handler;

    /**
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     * Send a bulk request and get the OidList back.
     *
     * @param int $maxRepetitions
     * @param int $nonRepeaters
     * @param string|Oid ...$oids
     * @return OidList
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function getBulk(int $maxRepetitions, int $nonRepeaters, ...$oids) : OidList
    {
        return $this->send(Requests::getBulk($maxRepetitions, $nonRepeaters, ...$oids))->getResponse()->getOids();
    }

    /**
     * Send a get next request to get the next variable(s) in the MIB tree back.
     *
     * @param string|Oid ...$oids
     * @return OidList
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function getNext(...$oids) : OidList
    {
        return $this->send(Requests::getNext(...$oids))->getResponse()->getOids();
    }

    /**
     * Get any number of OID objects as an OidList.
     *
     * @param string|Oid ...$oids
     * @return OidList
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function get(...$oids) : OidList
    {
        return $this->send(Requests::get(...$oids))->getResponse()->getOids();
    }

    /**
     * Get a single OID object. This contains the value object. If it doesn't exist, null is returned.
     *
     * @param string|Oid $oid
     * @return Oid|null
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function getOid($oid) : ?Oid
    {
        return $this->get($oid)->first();
    }

    /**
     * Get the string value of an OID. If it doesn't exist, it will return null.
     *
     * @param string|Oid $oid
     * @return null|string
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function getValue($oid) : ?string
    {
        $oid = $this->getOid($oid);

        return $oid ? (string) $oid->getValue() : null;
    }

    /**
     * Set one, or many, OID values.
     *
     * @param Oid ...$oids
     * @return MessageResponseInterface
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function set(...$oids)
    {
        return $this->send(Requests::set(...$oids));
    }

    /**
     * Sends an SNMP v2/3 style trap to a host.
     *
     * @param int|TimeTicksValue $sysUpTime
     * @param string|Oid $trapOid
     * @param Oid ...$oids
     * @return SnmpClient
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function sendTrap($sysUpTime, $trapOid, ...$oids)
    {
        $this->send(Requests::trap($sysUpTime, $trapOid, ...$oids));

        return $this;
    }

    /**
     * Sends an SNMP v1 style trap to a host.
     *
     * @param string $enterprise
     * @param string $address
     * @param int $genericType
     * @param int $specificType
     * @param int $sysUpTime
     * @param mixed ...$oids
     * @return $this
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function sendTrapV1(string $enterprise, string $address, int $genericType, int $specificType, int $sysUpTime, ...$oids)
    {
        $this->send(Requests::trapV1($enterprise, $address, $genericType, $specificType, $sysUpTime, ...$oids));

        return $this;
    }

    /**
     * Sends an Inform request to a host. This is a v2/3 trap that requires a response from the host.
     *
     * @param int|TimeTicksValue $sysUpTime
     * @param string|Oid $trapOid
     * @param Oid ...$oids
     * @return MessageResponseInterface
     * @throws ConnectionException
     * @throws SnmpRequestException
     */
    public function sendInform($sysUpTime, $trapOid, ...$oids) : MessageResponseInterface
    {
        return $this->send(Requests::inform($sysUpTime, $trapOid, ...$oids));
    }

    /**
     * Perform a walk using the SnmpWalk class helper.
     *
     * @param null|string $startAt
     * @param null|string $endAt
     * @return SnmpWalk
     */
    public function walk($startAt = null, $endAt = null) : SnmpWalk
    {
        return new SnmpWalk($this, $startAt, $endAt);
    }

    /**
     * Send a generic SNMP request and get the SNMP response back. Note that some requests do not generate a response.
     * In this case it will return null.
     *
     * @param RequestInterface $request
     * @param array $options
     * @return MessageResponseInterface
     * @throws ConnectionException
     * @throws Exception\SnmpRequestException
     */
    public function send(RequestInterface $request, array $options = []) : ?MessageResponseInterface
    {
        return $this->dispatcher()->handle($request, array_merge($this->options, $options));
    }

    /**
     * Get the client options.
     *
     * @return array
     */
    public function getOptions() : array
    {
        return $this->options;
    }

    /**
     * Set the client options.
     *
     * @param array $options
     * @return $this
     */
    public function setOptions(array $options)
    {
        $this->options = $options;

        return $this;
    }

    /**
     * @return ClientProtocolHandler
     */
    protected function dispatcher() : ClientProtocolHandler
    {
        if (!$this->handler) {
            $this->handler = $this->options['_protocol_handler'] ?? new ClientProtocolHandler($this->options);
        }

        return $this->handler;
    }
}
