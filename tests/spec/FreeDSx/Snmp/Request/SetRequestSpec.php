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
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Request\SetRequest;
use PhpSpec\ObjectBehavior;

class SetRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new OidList(Oid::fromInteger('1.2', 1), Oid::fromString('1.2.3', 'foo')));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SetRequest::class);
    }

    function it_should_implement_the_request_interface()
    {
        $this->shouldImplement(RequestInterface::class);
    }

    function it_should_be_an_instance_of_a_PDU()
    {
        $this->shouldImplement(Pdu::class);
    }

    function it_should_get_the_oid_list()
    {
        $this->getOids()->shouldBeLike(new OidList(Oid::fromInteger('1.2', 1), Oid::fromString('1.2.3', 'foo')));
    }

    function it_should_set_the_oid_list()
    {
        $this->setOids(new OidList(Oid::fromInteger('1.2.3',5)));
        $this->getOids()->shouldBeLike(new OidList(Oid::fromInteger('1.2.3',5)));
    }

    function it_should_get_the_pdu_tag()
    {
        $this->getPduTag()->shouldBeEqualTo(3);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(
            Asn1::context(3, Asn1::sequence(
                Asn1::integer(0),
                Asn1::integer(0),
                Asn1::integer(0),
                Asn1::sequenceOf(
                    Asn1::sequence(
                        Asn1::oid('1.2'),
                        OidValues::integer(1)->toAsn1()
                    ),
                    Asn1::sequence(
                        Asn1::oid('1.2.3'),
                        OidValues::string('foo')->toAsn1()
                    )
                )
            ))
        );
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $pdu = Asn1::sequence(
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    OidValues::string('foo')->toAsn1()
                )
            )
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $pdu = Asn1::context(3, $pdu)->setIsConstructed(true);

        $this::fromAsn1($pdu)->shouldBeLike(new SetRequest(new OidList(Oid::fromString('1.2.3', 'foo'))));
    }
}
