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
use FreeDSx\Snmp\Message\Response\MessageResponse;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Socket;

/**
 * Handles some common protocol handler functionality.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ProtocolTrait
{
    use IdGeneratorTrait;

    /**
     * @var null|Socket
     */
    protected $socket;

    /**
     * @var null|SnmpEncoder
     */
    protected $encoder;

    /**
     * @var null|Asn1MessageQueue
     */
    protected $queue;

    /**
     * @return Socket
     * @throws ConnectionException
     */
    protected function socket() : Socket
    {
        if (!$this->socket) {
            try {
                $this->socket = Socket::create($this->options['host'], [
                    'transport' => $this->options['transport'],
                    'port' => $this->options['port'],
                    'buffer_size' => ($this->options['transport'] === 'udp') ? 65507 : 8192,
                    'timeout_connect' => $this->options['timeout_connect'],
                    'timeout_read' => $this->options['timeout_read'],
                    'ssl_validate_cert' => $this->options['ssl_validate_cert'],
                    'ssl_allow_self_signed' => $this->options['ssl_allow_self_signed'],
                    'ssl_ca_cert' => $this->options['ssl_ca_cert'],
                    'ssl_peer_name' => $this->options['ssl_peer_name'],
                ]);
            } catch (\FreeDSx\Socket\Exception\ConnectionException $e) {
                throw new ConnectionException($e->getMessage(), $e->getCode(), $e);
            }
        }

        return $this->socket;
    }

    /**
     * @return SnmpEncoder
     */
    protected function encoder() : SnmpEncoder
    {
        if (!$this->encoder) {
            $this->encoder = new SnmpEncoder();
        }

        return $this->encoder;
    }

    /**
     * @return Asn1MessageQueue
     * @throws ConnectionException
     */
    protected function queue() : Asn1MessageQueue
    {
        if (!$this->queue) {
            $this->queue = new Asn1MessageQueue(
                $this->socket(),
                $this->encoder(),
                MessageResponse::class
            );
        }

        return $this->queue;
    }
}
