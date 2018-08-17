<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Exception;

use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Message\ErrorStatus;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\Response\MessageResponseV2;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Response\Response;
use FreeDSx\Snmp\Response\ResponseInterface;
use PhpSpec\ObjectBehavior;

class SnmpRequestExceptionSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new MessageResponseV2('foo', new Response(1, 2, 1, new OidList(
            new Oid('1.2.3')
        ))));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SnmpRequestException::class);
    }

    function it_should_extend_exception()
    {
        $this->shouldBeAnInstanceOf(\Exception::class);
    }

    function it_should_get_the_snmp_message()
    {
        $this->getSnmpMessage()->shouldBeAnInstanceOf(MessageResponseInterface::class);
    }

    function it_should_get_the_snmp_response()
    {
        $this->getResponse()->shouldBeAnInstanceOf(ResponseInterface::class);
    }

    function it_should_get_the_formatted_message()
    {
        $this->getMessage()->shouldBeEqualTo('The requested OID (1.2.3) cannot be returned (NoSuchName).');
    }

    function it_should_allow_overriding_the_message_if_specified_on_construction(MessageResponseInterface $response)
    {
        $this->beConstructedWith(new MessageResponseV2('foo', new Response(1, ErrorStatus::GEN_ERROR)), 'foo');

        $this->getMessage()->shouldBeEqualTo('foo');
    }

    function it_should_allow_the_snmp_message_to_be_nullable()
    {
        $this->beConstructedWith(null, 'foo');

        $this->getMessage()->shouldBeEqualTo('foo');
        $this->getSnmpMessage()->shouldBeNull();
        $this->getResponse()->shouldBeNull();
    }
}
