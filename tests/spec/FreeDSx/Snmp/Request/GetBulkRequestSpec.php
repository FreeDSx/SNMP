<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetBulkRequest;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Value\IntegerValue;
use PhpSpec\ObjectBehavior;

class GetBulkRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1, 2, new OidList(new Oid('1.2.3')));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(GetBulkRequest::class);
    }

    function it_should_implement_the_request_interface()
    {
        $this->shouldImplement(RequestInterface::class);
    }

    function it_should_be_an_instance_of_a_PDU()
    {
        $this->shouldBeAnInstanceOf(Pdu::class);
    }

    function it_should_get_the_max_repetitions()
    {
        $this->getMaxRepetitions()->shouldBeEqualTo(1);
    }

    function it_should_set_the_max_repetitions()
    {
        $this->setMaxRepetitions(2);
        $this->getMaxRepetitions()->shouldBeEqualTo(2);
    }

    function it_should_get_the_non_repeaters()
    {
        $this->getNonRepeaters()->shouldBeEqualTo(2);
    }

    function it_should_set_the_non_repeaters()
    {
        $this->setNonRepeaters(1);
        $this->getNonRepeaters()->shouldBeEqualTo(1);
    }

    function it_should_get_the_oid_list()
    {
        $this->getOids()->shouldBeLike(new OidList(new Oid('1.2.3')));
    }

    function it_should_set_the_oid_list()
    {
        $this->setOids(new OidList());
        $this->getOids()->shouldBeLike(new OidList());
    }

    function it_should_get_the_pdu_tag()
    {
        $this->getPduTag()->shouldBeEqualTo(5);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(
            Asn1::context(5, Asn1::sequence(
                Asn1::integer(0),
                Asn1::integer(2),
                Asn1::integer(1),
                Asn1::sequenceOf(
                    Asn1::sequence(
                        Asn1::oid('1.2.3'),
                        Asn1::null()
                    )
                )
            ))
        );
    }

    function it_should_ignore_oid_values_when_creating_the_asn1_representation()
    {
        $this->beConstructedWith(1, 2, new OidList(new Oid('1.2.3', new IntegerValue(1))));

        $this->toAsn1()->shouldBeLike(
            Asn1::context(5, Asn1::sequence(
                Asn1::integer(0),
                Asn1::integer(2),
                Asn1::integer(1),
                Asn1::sequenceOf(
                    Asn1::sequence(
                        Asn1::oid('1.2.3'),
                        Asn1::null()
                    )
                )
            ))
        );
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $pdu = Asn1::sequence(
            Asn1::integer(0),
            Asn1::integer(2),
            Asn1::integer(1),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    Asn1::null()
                )
            )
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $pdu = Asn1::context(5, $pdu)->setIsConstructed(true);

        $this::fromAsn1($pdu)->shouldBeLike(new GetBulkRequest(1, 2, new OidList(new Oid('1.2.3'))));
    }
}
