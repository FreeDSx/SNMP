<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Message;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use PhpSpec\ObjectBehavior;

class PduSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Pdu::class);
    }

    function it_should_implement_protocol_element_interface()
    {
        $this->shouldImplement(ProtocolElementInterface::class);
    }

    function it_should_get_the_id()
    {
        $this->getId()->shouldBeEqualTo(1);
    }

    function it_should_get_the_error_status()
    {
        $this->getErrorStatus()->shouldBeEqualTo(0);
    }

    function it_should_get_the_error_index()
    {
        $this->getErrorIndex()->shouldBeEqualTo(0);
    }

    function it_should_get_the_oid_list()
    {
        $this->getOids()->shouldBeLike(new OidList());
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(0, Asn1::sequence(
            Asn1::integer(1),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::sequenceOf()
        )));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $pdu = Asn1::sequence(
            Asn1::integer(1),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::sequenceOf()
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $pdu = Asn1::context(0, $pdu)->setIsConstructed(true);

        $this::fromAsn1($pdu)->shouldBeLike(new Pdu(1));
    }
}
