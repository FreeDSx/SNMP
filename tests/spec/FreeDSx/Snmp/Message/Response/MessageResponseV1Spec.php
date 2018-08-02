<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Message\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Message\AbstractMessage;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\Response\MessageResponseV1;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Response\Response;
use PhpSpec\ObjectBehavior;

class MessageResponseV1Spec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', new Response(0));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(MessageResponseV1::class);
    }

    function it_should_implement_MessageResponseInterface()
    {
        $this->shouldImplement(MessageResponseInterface::class);
    }

    function it_should_extend_abstract_message()
    {
        $this->shouldBeAnInstanceOf(AbstractMessage::class);
    }

    function it_should_get_the_community()
    {
        $this->getCommunity()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_version()
    {
        $this->getVersion()->shouldBeEqualTo(0);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::integer(0),
            Asn1::octetString('foo'),
            (new Response(0))->toAsn1()
        ));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $encoder = new SnmpEncoder();

        $pdu = '';
        foreach ((new Response(0))->toAsn1() as $child) {
            $pdu .= $encoder->encode($child);
        }

        $this::fromAsn1(Asn1::sequence(
            Asn1::integer(0),
            Asn1::octetString('foo'),
            Asn1::context(2, new IncompleteType($pdu))->setIsConstructed(true)

        ))->shouldBeLike(new MessageResponseV1('foo', new Response(0)));
    }
}
