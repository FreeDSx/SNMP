<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp;

use FreeDSx\Snmp\Server\ServerRunner\TrapServerRunner;
use FreeDSx\Snmp\Trap\TrapListenerInterface;
use FreeDSx\Snmp\TrapSink;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class TrapSinkSpec extends ObjectBehavior
{
    function let(TrapListenerInterface $listener)
    {
        $this->beConstructedWith($listener);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(TrapSink::class);
    }

    function it_should_get_the_options()
    {
        $this->getOptions()->shouldBeEqualTo([
            'ip' => '0.0.0.0',
            'port' => 162,
            'transport' => 'udp',
            'version' => null,
            'community' => null,
            'whitelist' => null,
            'timeout_connect' => 5,
        ]);
    }

    function it_should_set_the_server_runner(TrapServerRunner $runner)
    {
        $this->setServer($runner);
    }

    function it_should_listen_for_traps(TrapServerRunner $runner, $listener)
    {
        $this->beConstructedWith($listener, ['port' => 11162]);
        $this->setServer($runner);

        $runner->run(Argument::type(Socket::class))->shouldBeCalled();
        $this->listen();
    }
}
