<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Protocol\Factory;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Protocol\Factory\OidValueFactory;
use PhpSpec\ObjectBehavior;

class OidValueFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(OidValueFactory::class);
    }

    function it_should_get_the_ip_address_value_object()
    {
        $this::get(Asn1::application(0, new IncompleteType(hex2bin('7f000001'))))->shouldBeLike(OidValues::ipAddress('127.0.0.1'));
    }

    function it_should_get_the_counter_value_object()
    {
        $this::get(Asn1::application(1, new IncompleteType("\x09")))->shouldBeLike(OidValues::counter(9));
    }

    function it_should_get_the_unsigned_integer_value_object()
    {
        $this::get(Asn1::application(2, new IncompleteType("\x09")))->shouldBeLike(OidValues::unsignedInteger(9));
    }

    function it_should_get_the_timeticks_value_object()
    {
        $this::get(Asn1::application(3, new IncompleteType("\x09")))->shouldBeLike(OidValues::timeticks(9));
    }

    function it_should_get_the_arbitrary_value_object()
    {
        $this::get(Asn1::application(4, new IncompleteType("foo")))->shouldBeLike(OidValues::arbitrary('foo'));
    }

    function it_should_get_the_big_counter_value_object()
    {
        $this::get(Asn1::application(6, new IncompleteType("\x09")))->shouldBeLike(OidValues::bigCounter(9));
    }

    function it_should_get_the_integer_type_value_object()
    {
        $this::get(OidValues::integer(1)->toAsn1())->shouldBeLike(OidValues::integer(1));
    }

    function it_should_get_the_string_type_value_object()
    {
        $this::get(OidValues::string('foo')->toAsn1())->shouldBeLike(OidValues::string('foo'));
    }

    function it_should_get_the_oid_type_value_object()
    {
        $this::get(OidValues::oid('1.2.3')->toAsn1())->shouldBeLike(OidValues::oid('1.2.3'));
    }

    function it_should_throw_an_exception_if_the_value_type_doesnt_have_a_mapping()
    {
        $this->shouldThrow(ProtocolException::class)->during('get', [Asn1::null()]);
        $this->shouldThrow(ProtocolException::class)->during('get', [Asn1::application(99, new IncompleteType("foo"))]);
    }
}
