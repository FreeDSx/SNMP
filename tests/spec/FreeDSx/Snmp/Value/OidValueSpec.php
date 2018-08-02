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
use FreeDSx\Snmp\Value\OidValue;
use PhpSpec\ObjectBehavior;

class OidValueSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('1.2.3');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(OidValue::class);
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
        $this->getValue()->shouldBeEqualTo('1.2.3');
    }

    function it_should_set_the_value()
    {
        $this->setValue('1.2');
        $this->getValue()->shouldBeEqualTo('1.2');
    }

    function it_should_check_if_the_value_equals_a_specific_value()
    {
        $this->equals('1.2.3')->shouldBeEqualTo(true);
        $this->equals('bar')->shouldBeEqualTo(false);
    }

    function it_should_have_a_string_representation()
    {
        $this->__toString()->shouldBeEqualTo('1.2.3');
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::oid('1.2.3'));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $this::fromAsn1(Asn1::oid('1.2.3'))->shouldBeLike(new OidValue('1.2.3'));
    }
}
