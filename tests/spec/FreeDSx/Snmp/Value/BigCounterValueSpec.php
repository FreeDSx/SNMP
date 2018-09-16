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
use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Value\AbstractValue;
use FreeDSx\Snmp\Value\BigCounterValue;
use PhpSpec\ObjectBehavior;

class BigCounterValueSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(9000);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(BigCounterValue::class);
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
        $this->getValue()->shouldBeEqualTo(9000);
    }

    function it_should_set_the_value()
    {
        $this->setValue(1);
        $this->getValue()->shouldBeEqualTo(1);
    }

    function it_should_check_if_the_value_equals_a_specific_value()
    {
        $this->equals(9000)->shouldBeEqualTo(true);
        $this->equals(1)->shouldBeEqualTo(false);
    }

    function it_should_check_if_the_value_equals_a_specific_value_non_strict()
    {
        $this->equals('9000', false)->shouldBeEqualTo(true);
    }

    function it_should_have_a_string_representation()
    {
        $this->__toString()->shouldBeEqualTo('9000');
    }

    function it_should_check_whether_the_value_is_a_bigint()
    {
        $this->isBigInt()->shouldBeEqualTo(false);
        $this->setValue('18446744073709551615');
        $this->isBigInt()->shouldBeEqualTo(true);
    }

    function it_should_be_constructed_from_a_bigint_string_value()
    {
        $this->beConstructedWith('18446744073709551615');
        $this->getValue()->shouldBeEqualTo('18446744073709551615');
    }

    function it_should_set_a_bigint_value()
    {
        $this->setValue('18446744073709551615');
        $this->getValue()->shouldBeEqualTo('18446744073709551615');
    }

    function it_should_not_allow_non_numeric_integers_during_construction()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('__construct', ['foo']);
        $this->shouldThrow(InvalidArgumentException::class)->during('__construct', ['15.5']);
    }

    function it_should_not_allow_non_numeric_integers_during_set()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('setValue', ['foo']);
        $this->shouldThrow(InvalidArgumentException::class)->during('setValue', ['15.5']);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(6, Asn1::integer(9000)));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $this::fromAsn1(Asn1::application(6, new IncompleteType("\x01")))->shouldBeLike(new BigCounterValue(1));
    }
}
