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
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Value\AbstractValue;
use FreeDSx\Snmp\Value\StringValue;
use PhpSpec\ObjectBehavior;

class StringValueSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(StringValue::class);
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
        $this->getValue()->shouldBeEqualTo('foo');
    }

    function it_should_set_the_value()
    {
        $this->setValue('bar');
        $this->getValue()->shouldBeEqualTo('bar');
    }

    function it_should_check_if_the_value_equals_a_specific_value()
    {
        $this->equals('foo')->shouldBeEqualTo(true);
        $this->equals('bar')->shouldBeEqualTo(false);
    }

    function it_should_have_a_string_representation()
    {
        $this->__toString()->shouldBeEqualTo('foo');
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::octetString('foo'));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $this::fromAsn1(Asn1::octetString('foo'))->shouldBeLike(new StringValue('foo'));
    }
}
