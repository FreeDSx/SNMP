<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Response\ReportResponse;
use FreeDSx\Snmp\Response\ResponseInterface;
use PhpSpec\ObjectBehavior;

class ReportResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1, 2, 1, new OidList(Oid::fromCounter('1.2.3', 1)));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ReportResponse::class);
    }

    function it_should_implement_the_response_interface()
    {
        $this->shouldImplement(ResponseInterface::class);
    }

    function it_should_be_an_instance_of_a_PDU()
    {
        $this->shouldBeAnInstanceOf(Pdu::class);
    }

    function it_should_get_the_oid_list()
    {
        $this->getOids()->shouldBeLike(new OidList(Oid::fromCounter('1.2.3', 1)));
    }

    function it_should_get_the_id()
    {
        $this->getId()->shouldBeEqualTo(1);
    }

    function it_should_get_the_error_status()
    {
        $this->getErrorStatus()->shouldBeEqualTo(2);
    }

    function it_should_get_the_error_index()
    {
        $this->getErrorIndex()->shouldBeEqualTo(1);
    }

    function it_should_get_the_pdu_tag()
    {
        $this->getPduTag()->shouldBeEqualTo(8);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(8, Asn1::sequence(
            Asn1::integer(1),
            Asn1::integer(2),
            Asn1::integer(1),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    OidValues::counter(1)->toAsn1()
                )
            )
        )));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $pdu = Asn1::sequence(
            Asn1::integer(1),
            Asn1::integer(2),
            Asn1::integer(1),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    OidValues::counter(1)->toAsn1()
                )
            )
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $pdu = Asn1::context(8, $pdu)->setIsConstructed(true);

        $this::fromAsn1($pdu)->shouldBeLike(new ReportResponse(1, 2, 1, new OidList(Oid::fromCounter('1.2.3', 1))));
    }
}
