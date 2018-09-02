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

use FreeDSx\Snmp\Exception\UnexpectedValueException;
use FreeDSx\Snmp\Message\EngineId;
use PhpSpec\ObjectBehavior;

class EngineIdSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('10.43.1.235', EngineId::FORMAT_IPV4);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(EngineId::class);
    }

    function it_should_get_the_format()
    {
        $this->getFormat()->shouldBeEqualTo(EngineId::FORMAT_IPV4);
    }

    function it_should_get_the_enterprise_number()
    {
        $this->getEnterpriseId()->shouldBeEqualTo(EngineId::ENTERPRISE_NUMBER);
    }

    function it_should_get_whether_it_is_rfc3411_formatted_or_not()
    {
        $this->isVariableLengthFormat()->shouldBeEqualTo(true);
    }

    function it_should_get_the_hexadecimal_representation()
    {
        $this->toHex()->shouldBeEqualTo('8000cd54010a2b01eb');
    }

    function it_should_have_a_string_representation_as_hex()
    {
        $this->__toString()->shouldBeEqualTo('8000cd54010a2b01eb');
    }

    function it_should_get_the_binary_representation_for_ipv4()
    {
        $this->toBinary()->shouldBeEqualTo(hex2bin('8000cd54010a2b01eb'));
    }

    function it_should_get_the_binary_representation_for_ipv6()
    {
        $this->beConstructedWith('fe80::214:4fff:fe80:e187', EngineId::FORMAT_IPV6);
        $this->toBinary()->shouldBeEqualTo(hex2bin('8000cd5402fe80000002144ffffe80e187'));
    }

    function it_should_get_the_binary_representation_for_mac()
    {
        $this->beConstructedWith('08:00:27:18:f1:0e', EngineId::FORMAT_MAC);
        $this->toBinary()->shouldBeEqualTo(hex2bin('8000cd540308002718f10e'));
    }

    function it_should_get_the_binary_representation_for_text()
    {
        $this->beConstructedWith('Fred', EngineId::FORMAT_TEXT);
        $this->toBinary()->shouldBeEqualTo(hex2bin('8000cd540446726564'));
    }

    function it_should_get_the_binary_representation_for_octet()
    {
        $this->beConstructedWith('01 04 03 33', EngineId::FORMAT_OCTET);
        $this->toBinary()->shouldBeEqualTo(hex2bin('8000cd540501040333'));
    }

    function it_should_pad_delimited_octets_as_needed_for_binary()
    {
        $this->beConstructedWith('0 1 02 03', EngineId::FORMAT_OCTET);
        $this->toBinary()->shouldBeEqualTo(hex2bin('8000cd540500010203'));

    }

    function it_should_parse_binary_ipv4()
    {
        $this::fromBinary(hex2bin('8000cd54010a2b01eb'))->shouldBeLike(new EngineId('10.43.1.235', EngineId::FORMAT_IPV4));
    }

    function it_should_parse_binary_ipv6()
    {
        $this::fromBinary(hex2bin('8000cd5402fe80000002144ffffe80e187'))->shouldBeLike(new EngineId('fe80::214:4fff:fe80:e187', EngineId::FORMAT_IPV6));
    }

    function it_should_parse_binary_mac()
    {
        $this::fromBinary(hex2bin('8000cd540308002718f10e'))->shouldBeLike(new EngineId('08:00:27:18:f1:0e', EngineId::FORMAT_MAC));
    }

    function it_should_parse_binary_text()
    {
        $this::fromBinary(hex2bin('8000cd540446726564'))->shouldBeLike(new EngineId('Fred', EngineId::FORMAT_TEXT));
    }

    function it_should_parse_binary_octets()
    {
        $this::fromBinary(hex2bin('8000cd540501040333'))->shouldBeLike(new EngineId('01040333', EngineId::FORMAT_OCTET));
    }

    function it_should_parse_an_enterprise_specific_binary_format()
    {
        $this::fromBinary(hex2bin('80001f8880e9f66b557e52285b00000000'))->shouldBeLike(new EngineId(hex2bin('e9f66b557e52285b00000000'), 128, 8072));
    }

    function it_should_parse_binary_rfc1910()
    {
        $this::fromBinary(hex2bin('00001f88e9f66b557e52285b'))->shouldBeLike(new EngineId(hex2bin('e9f66b557e52285b'), null, 8072));
    }

    function it_should_be_constructed_using_ipv4()
    {
        $this::fromIPv4('192.168.1.1') -> shouldBeLike(new EngineId('192.168.1.1', EngineId::FORMAT_IPV4));
    }

    function it_should_be_constructed_using_ipv6()
    {
        $this::fromIPv6('fe80::214:4fff:fe80:e187') -> shouldBeLike(new EngineId('fe80::214:4fff:fe80:e187', EngineId::FORMAT_IPV6));
    }

    function it_should_be_constructed_using_mac()
    {
        $this::fromMAC('08:00:27:18:f1:0e') -> shouldBeLike(new EngineId('08:00:27:18:f1:0e', EngineId::FORMAT_MAC));
    }

    function it_should_be_constructed_using_text()
    {
        $this::fromText('Fred') -> shouldBeLike(new EngineId('Fred', EngineId::FORMAT_TEXT));
    }

    function it_should_be_constructed_using_octets()
    {
        $this::fromOctet('00 01 02 03') -> shouldBeLike(new EngineId('00 01 02 03', EngineId::FORMAT_OCTET));
    }

    function it_should_be_constructed_using_rfc1910()
    {
        $this::fromRFC1910('Fred')->shouldBeLike(new EngineId('Fred', null));
    }

    function it_should_throw_an_exception_if_it_is_all_00()
    {
        $this->shouldThrow(new UnexpectedValueException('The engine ID is malformed.'))->during('fromBinary', [hex2bin('000000000000')]);
    }

    function it_should_throw_an_excecption_if_it_is_all_FF()
    {
        $this->shouldThrow(new UnexpectedValueException('The engine ID is malformed.'))->during('fromBinary', [hex2bin('ffffffffffff')]);
    }

    function it_should_throw_an_exception_on_invalid_ipv4_length_in_binary()
    {
        $this->shouldThrow(new UnexpectedValueException('Expected 4 bytes for IPv4, got 5.'))->during('fromBinary', [hex2bin('8000cd54010a2b01ebff')]);
        $this->shouldThrow(new UnexpectedValueException('Expected 4 bytes for IPv4, got 3.'))->during('fromBinary', [hex2bin('8000cd54010a2b01')]);
    }

    function it_should_throw_an_exception_on_invalid_ipv4()
    {
        $this->beConstructedWith('0.0.0', EngineId::FORMAT_IPV4);
        $this->shouldThrow(new UnexpectedValueException('The IPv4 address is invalid: 0.0.0'))->during('toBinary');
    }

    function it_should_throw_an_exception_on_invalid_ipv6_length_in_binary()
    {
        $this->shouldThrow(new UnexpectedValueException('Expected 12 bytes for IPv6, got 13.'))->during('fromBinary', [hex2bin('8000cd5402fe80000002144ffffe80e187ff')]);
        $this->shouldThrow(new UnexpectedValueException('Expected 12 bytes for IPv6, got 11.'))->during('fromBinary', [hex2bin('8000cd5402fe80000002144ffffe80e1')]);
    }

    function it_should_throw_an_exception_on_invalid_ipv6()
    {
        $this->beConstructedWith('12:33a2:::', EngineId::FORMAT_IPV6);
        $this->shouldThrow(new UnexpectedValueException('The IPv6 address is invalid: 12:33a2:::'))->during('toBinary');
    }

    function it_should_throw_an_exception_on_invalid_mac_length_in_binary()
    {
        $this->shouldThrow(new UnexpectedValueException('Expected 6 bytes for a MAC, got 7.'))->during('fromBinary', [hex2bin('8000cd540308002718f10eaa')]);
        $this->shouldThrow(new UnexpectedValueException('Expected 6 bytes for a MAC, got 5.'))->during('fromBinary', [hex2bin('8000cd540308002718f1')]);
    }

    function it_should_throw_an_exception_on_invalid_mac()
    {
        $this->beConstructedWith('1:2:3:4:5:6', EngineId::FORMAT_MAC);
        $this->shouldThrow(new UnexpectedValueException('The MAC is invalid: 1:2:3:4:5:6'))->during('toBinary');
    }

    function it_should_throw_an_exception_on_invalid_octets()
    {
        $this->beConstructedWith('01za', EngineId::FORMAT_OCTET);
        $this->shouldThrow(new UnexpectedValueException('The octets contains invalid values.'))->during('toBinary');
    }

    function it_should_throw_an_exception_on_uneven_length_octets()
    {
        $this->beConstructedWith('a1a', EngineId::FORMAT_OCTET);
        $this->shouldThrow(new UnexpectedValueException('The octets must be an even length.'))->during('toBinary');
    }
}
