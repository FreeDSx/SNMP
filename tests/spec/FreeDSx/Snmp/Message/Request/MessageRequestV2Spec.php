<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Message\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Message\AbstractMessage;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Request\MessageRequestV2;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetRequest;
use PhpSpec\ObjectBehavior;

class MessageRequestV2Spec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', new GetRequest(new OidList()));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(MessageRequestV2::class);
    }

    function it_should_implement_MessageRequestInterface()
    {
        $this->shouldImplement(MessageRequestInterface::class);
    }

    function it_should_extend_abstract_message()
    {
        $this->shouldBeAnInstanceOf(AbstractMessage::class);
    }

    function it_should_get_the_community()
    {
        $this->getCommunity()->shouldBeEqualTo('foo');
    }

    function it_should_set_the_community()
    {
        $this->setCommunity('bar');

        $this->getCommunity()->shouldBeEqualTo('bar');
    }

    function it_should_get_the_version()
    {
        $this->getVersion()->shouldBeEqualTo(1);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::integer(1),
            Asn1::octetString('foo'),
            (new GetRequest(new OidList()))->toAsn1()
        ));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $encoder = new SnmpEncoder();

        $pdu = '';
        foreach ((new GetRequest(new OidList()))->toAsn1() as $child) {
            $pdu .= $encoder->encode($child);
        }

        $this::fromAsn1(Asn1::sequence(
            Asn1::integer(1),
            Asn1::octetString('foo'),
            Asn1::context(0, new IncompleteType($pdu))->setIsConstructed(true)

        ))->shouldBeLike(new MessageRequestV2('foo', new GetRequest(new OidList())));
    }
}
