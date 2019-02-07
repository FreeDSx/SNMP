<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Value\BigCounterValue;
use FreeDSx\Snmp\Value\CounterValue;
use FreeDSx\Snmp\Value\IntegerValue;
use FreeDSx\Snmp\Value\IpAddressValue;
use FreeDSx\Snmp\Value\OidValue;
use FreeDSx\Snmp\Value\StringValue;
use FreeDSx\Snmp\Value\TimeTicksValue;
use FreeDSx\Snmp\Value\UnsignedIntegerValue;
use PhpSpec\ObjectBehavior;

class OidSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('1.2.3.4.5', new IntegerValue(1));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Oid::class);
    }

    function it_should_implement_ProtocolElementInterface()
    {
        $this->shouldImplement(ProtocolElementInterface::class);
    }

    function it_should_get_the_string_oid()
    {
        $this->getOid()->shouldBeEqualTo('1.2.3.4.5');
    }

    function it_should_set_the_string_oid()
    {
        $this->setOid('1.2');
        $this->getOid()->shouldBeEqualTo('1.2');
    }

    function it_should_get_the_value()
    {
        $this->getValue()->shouldBeLike(new IntegerValue(1));
    }

    function it_should_set_the_value()
    {
        $this->setValue(null);
        $this->getValue()->shouldBeNull();

        $this->setValue(new StringValue('foo'));
        $this->getValue()->shouldBeLike(new StringValue('foo'));
    }

    function it_should_get_the_status()
    {
        $this->getStatus()->shouldBeNull();
    }

    function it_should_set_the_status()
    {
        $this->setStatus(Oid::STATUS_END_OF_MIB_VIEW);
        $this->getStatus()->shouldBeEqualTo(Oid::STATUS_END_OF_MIB_VIEW);
    }

    function it_should_check_if_it_has_a_specific_status()
    {
        $this->hasStatus(Oid::STATUS_END_OF_MIB_VIEW)->shouldBeEqualTo(false);
        $this->setStatus(Oid::STATUS_END_OF_MIB_VIEW);
        $this->hasStatus(Oid::STATUS_END_OF_MIB_VIEW)->shouldBeEqualTo(true);
    }

    function it_should_check_if_the_status_is_the_end_of_the_mib_view()
    {
        $this->isEndOfMibView()->shouldBeEqualTo(false);
        $this->setStatus(Oid::STATUS_END_OF_MIB_VIEW);
        $this->isEndOfMibView()->shouldBeEqualTo(true);
    }

    function it_should_check_if_the_status_is_no_such_object()
    {
        $this->isNoSuchObject()->shouldBeEqualTo(false);
        $this->setStatus(Oid::STATUS_NO_SUCH_OBJECT);
        $this->isNoSuchObject()->shouldBeEqualTo(true);
    }

    function it_should_check_if_the_status_is_no_such_instance()
    {
        $this->isNoSuchInstance()->shouldBeEqualTo(false);
        $this->setStatus(Oid::STATUS_NO_SUCH_INSTANCE);
        $this->isNoSuchInstance()->shouldBeEqualTo(true);
    }

    function it_should_have_a_string_representation()
    {
        $this->__toString()->shouldBeEqualTo('1.2.3.4.5');
    }

    function it_should_be_constructed_using_a_string_value()
    {
        $this::fromString('1.2.3','foo')->shouldBeLike(new Oid('1.2.3', new StringValue('foo')));
    }

    function it_should_be_constructed_using_an_ip_address_value()
    {
        $this::fromIpAddress('1.2.3','127.0.0.1')->shouldBeLike(new Oid('1.2.3', new IpAddressValue('127.0.0.1')));
    }

    function it_should_be_constructed_using_a_timeticks_value()
    {
        $this::fromTimeticks('1.2.3',1)->shouldBeLike(new Oid('1.2.3', new TimeTicksValue(1)));
    }

    function it_should_be_constructed_using_a_counter_value()
    {
        $this::fromCounter('1.2.3',1)->shouldBeLike(new Oid('1.2.3', new CounterValue(1)));
    }

    function it_should_be_constructed_using_a_big_counter_value()
    {
        $this::fromBigCounter('1.2.3',1)->shouldBeLike(new Oid('1.2.3', new BigCounterValue(1)));
    }

    function it_should_be_constructed_using_an_integer_value()
    {
        $this::fromInteger('1.2.3',1)->shouldBeLike(new Oid('1.2.3', new IntegerValue(1)));
    }

    function it_should_be_constructed_using_an_oid_value()
    {
        $this::fromOid('1.2.3','1.2')->shouldBeLike(new Oid('1.2.3', new OidValue('1.2')));
    }

    function it_should_be_constructed_using_an_unsigned_int()
    {
        $this::fromUnsignedInt('1.2.3',1)->shouldBeLike(new Oid('1.2.3', new UnsignedIntegerValue(1)));
    }

    function it_should_have_an_ASN1_representation_with_a_value()
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::oid('1.2.3.4.5'),
            OidValues::integer(1)->toAsn1()
        ));
    }

    function it_should_have_an_ASN1_representation_without_a_value()
    {
        $this->beConstructedWith('1.2.3.4.5', null);

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::oid('1.2.3.4.5'),
            Asn1::null()
        ));
    }

    function it_should_have_an_ASN1_representation_with_a_status()
    {
        $this->beConstructedWith('1.2.3.4.5', null, Oid::STATUS_NO_SUCH_INSTANCE);

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::oid('1.2.3.4.5'),
            Asn1::context(Oid::STATUS_NO_SUCH_INSTANCE, Asn1::null())
        ));
    }

    function it_should_have_an_ASN1_representation_with_a_leading_dot_notation()
    {
        $this->beConstructedWith('.1.2.3.4.5', null);

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::oid('1.2.3.4.5'),
            Asn1::null()
        ));
    }

    function it_should_be_constructed_from_an_ASN1_representation_with_a_value()
    {
        $this::fromAsn1(Asn1::sequence(
            Asn1::oid('1.2.3.4.5'),
            OidValues::integer(1)->toAsn1()
        ))->shouldBeLike(new Oid('1.2.3.4.5', OidValues::integer(1)));
    }

    function it_should_be_constructed_from_an_ASN1_representation_without_a_value()
    {
        $this::fromAsn1(Asn1::sequence(
            Asn1::oid('1.2.3.4.5'),
            Asn1::null()
        ))->shouldBeLike(new Oid('1.2.3.4.5', null));
    }

    function it_should_be_constructed_from_an_ASN1_representation_with_a_status()
    {
        $value = (new IncompleteType(''))
            ->setTagNumber(1)
            ->setTagClass(AbstractType::TAG_CLASS_CONTEXT_SPECIFIC);
        $this::fromAsn1(Asn1::sequence(
            Asn1::oid('1.2.3.4.5'),
            $value
        ))->shouldBeLike(new Oid('1.2.3.4.5', null, Oid::STATUS_NO_SUCH_INSTANCE));
    }
}
