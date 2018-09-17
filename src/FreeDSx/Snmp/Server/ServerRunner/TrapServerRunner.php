<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Server\ServerRunner;

use FreeDSx\Snmp\Protocol\TrapProtocolHandler;
use FreeDSx\Socket\SocketServer;

/**
 * Server for synchronous trap request handling.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TrapServerRunner implements ServerRunnerInterface
{
    /**
     * @var array
     */
    protected $options;

    /**
     * @var TrapProtocolHandler
     */
    protected $handler;

    /**
     * @param TrapProtocolHandler|null $handler
     * @param array $options
     */
    public function __construct(TrapProtocolHandler $handler, array $options = [])
    {
        $this->options = $options;
        $this->handler = $handler;
    }

    /**
     * {@inheritdoc}
     */
    public function run(SocketServer $server)
    {
        while ($data = $server->receive($ipAddress)) {
            try {
                $this->handler->handle($ipAddress, $data, $this->options);
            } catch (\Exception|\Throwable $e) {
            }
        }
    }
}
