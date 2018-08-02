<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Value;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Value\AbstractValue;
use FreeDSx\Snmp\Value\IpAddressValue;
use PhpSpec\ObjectBehavior;

class IpAddressValueSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('127.0.0.1');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(IpAddressValue::class);
    }

    function it_should_extend_the_abstract_value()
    {
        $this->shouldBeAnInstanceOf(AbstractValue::class);
    }

    function it_should_implement_the_ProtocolElementInterface()
    {
        $this->shouldImplement(ProtocolElementInterface::class);
    }

    function it_should_get_the_value()
    {
        $this->getValue()->shouldBeEqualTo('127.0.0.1');
    }

    function it_should_set_the_value()
    {
        $this->setValue('127.0.0.2');
        $this->getValue()->shouldBeEqualTo('127.0.0.2');
    }

    function it_should_check_if_the_value_equals_a_specific_value()
    {
        $this->equals('127.0.0.1')->shouldBeEqualTo(true);
        $this->equals('127.0.0.2')->shouldBeEqualTo(false);
    }

    function it_should_have_a_string_representation()
    {
        $this->__toString()->shouldBeEqualTo('127.0.0.1');
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(0, Asn1::octetString(hex2bin('7f000001'))));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $this::fromAsn1(Asn1::application(0, new IncompleteType(hex2bin('7f000001'))))->shouldBeLike(new IpAddressValue('127.0.0.1'));
    }
}
