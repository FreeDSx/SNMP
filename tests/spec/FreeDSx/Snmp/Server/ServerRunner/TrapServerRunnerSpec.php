<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Server\ServerRunner;

use FreeDSx\Snmp\Protocol\TrapProtocolHandler;
use FreeDSx\Snmp\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Snmp\Server\ServerRunner\TrapServerRunner;
use PhpSpec\ObjectBehavior;

/**
 * @todo Cannot get spec to work correctly with the run method against the SocketServer. Need to revist.
 */
class TrapServerRunnerSpec extends ObjectBehavior
{
    function let(TrapProtocolHandler $handler)
    {
        $this->beConstructedWith($handler);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(TrapServerRunner::class);
    }

    function it_should_implement_the_server_runner_interface()
    {
        $this->shouldImplement(ServerRunnerInterface::class);
    }
}
