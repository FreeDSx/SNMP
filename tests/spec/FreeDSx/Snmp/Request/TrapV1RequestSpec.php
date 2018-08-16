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
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Value\IpAddressValue;
use FreeDSx\Snmp\Value\TimeTicksValue;
use PhpSpec\ObjectBehavior;

class TrapV1RequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('1.2.3', OidValues::ipAddress('192.168.1.1'), 1, 2, OidValues::timeticks(1), new OidList(Oid::fromCounter('1.2.3', 1)));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(TrapV1Request::class);
    }

    function it_should_implement_the_request_interface()
    {
        $this->shouldImplement(RequestInterface::class);
    }

    function it_should_get_the_oid_list()
    {
        $this->getOids()->shouldBeLike(new OidList(Oid::fromCounter('1.2.3', 1)));
    }

    function it_should_set_the_oid_list()
    {
        $this->setOids(new OidList());
        $this->getOids()->shouldBeLike(new OidList());
    }

    function it_should_get_the_enterprise()
    {
        $this->getEnterprise()->shouldBeEqualTo('1.2.3');
    }

    function it_should_set_the_enterprise()
    {
        $this->setEnterprise('1.2');
        $this->getEnterprise()->shouldBeEqualTo('1.2');
    }

    function it_should_get_the_generic_type()
    {
        $this->getGenericType()->shouldBeEqualTo(1);
    }

    function it_should_set_the_generic_type()
    {
        $this->setGenericType(3);
        $this->getGenericType()->shouldBeEqualTo(3);
    }

    function it_should_get_the_specific_type()
    {
        $this->getSpecificType()->shouldBeEqualTo(2);
    }

    function it_should_set_the_specific_type()
    {
        $this->setSpecificType(3);
        $this->getSpecificType()->shouldBeEqualTo(3);
    }

    function it_should_get_the_ip_address()
    {
        $this->getIpAddress()->shouldBeLike(new IpAddressValue('192.168.1.1'));
    }

    function it_should_set_the_ip_address()
    {
        $this->setIpAddress(new IpAddressValue('127.0.0.1'));
        $this->getIpAddress()->shouldBeLike(new IpAddressValue('127.0.0.1'));
    }

    function it_should_get_the_sysUpTime()
    {
        $this->getSysUpTime()->shouldBeLike(new TimeTicksValue(1));
    }

    function it_should_set_the_sysUpTime()
    {
        $this->setSysUpTime(OidValues::timeticks(2));
        $this->getSysUpTime()->shouldBeLike(OidValues::timeticks(2));
    }

    function it_should_get_the_pdu_tag()
    {
        $this->getPduTag()->shouldBeEqualTo(4);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(4, Asn1::sequence(
            Asn1::oid('1.2.3'),
            OidValues::ipAddress('192.168.1.1')->toAsn1(),
            Asn1::integer(1),
            Asn1::integer(2),
            OidValues::timeticks(1)->toAsn1(),
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
            Asn1::oid('1.2.3'),
            OidValues::ipAddress('192.168.1.1')->toAsn1(),
            Asn1::integer(1),
            Asn1::integer(2),
            OidValues::timeticks(1)->toAsn1(),
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
        $pdu = Asn1::context(4, $pdu)->setIsConstructed(true);

        $this::fromAsn1($pdu)->shouldBeLike(new TrapV1Request('1.2.3', OidValues::ipAddress('192.168.1.1'), 1, 2, OidValues::timeticks(1), new OidList(Oid::fromCounter('1.2.3', 1))));
    }
}
