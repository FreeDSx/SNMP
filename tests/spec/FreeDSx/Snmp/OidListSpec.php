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
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use PhpSpec\ObjectBehavior;

class OidListSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new Oid('5.4.3.2.1'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(OidList::class);
    }

    function it_should_implement_ProtocolElementInterface()
    {
        $this->shouldImplement(ProtocolElementInterface::class);
    }

    function it_should_implement_countable()
    {
        $this->shouldImplement(\Countable::class);
    }

    function it_should_implement_iterator_aggregate()
    {
        $this->shouldImplement(\IteratorAggregate::class);
    }

    function it_should_add_an_oid()
    {
        $this->add(new Oid('1.2.3'));
        $this->get('1.2.3')->shouldBeAnInstanceOf(Oid::class);
    }

    function it_should_check_if_an_oid_exists()
    {
        $this->has('1.2.3')->shouldBeEqualTo(false);
        $this->has('5.4.3.2.1')->shouldBeEqualTo(true);
    }

    function it_should_get_a_specific_oid()
    {
        $this->get('5.4.3.2.1')->shouldBeLike(new Oid('5.4.3.2.1'));
    }

    function it_should_return_null_getting_an_oid_that_doesnt_exist()
    {
        $this->get('2.2.2')->shouldBeNull();
    }

    function it_should_get_an_oid_by_the_index()
    {
        $this->index(1)->shouldBeLike(new Oid('5.4.3.2.1'));
    }

    function it_should_return_null_if_the_index_doesnt_exist()
    {
        $this->index(99)->shouldBeNull();
    }

    function it_should_get_the_first_oid()
    {
        $this->first()->shouldBeLike(new Oid('5.4.3.2.1'));
    }

    function it_should_get_null_if_the_first_oid_doesnt_exist()
    {
        $this->beConstructedWith(...[]);

        $this->first()->shouldBeNull();
    }

    function it_should_get_the_last_oid()
    {
        $this->last()->shouldBeLike(new Oid('5.4.3.2.1'));
    }

    function it_should_get_null_if_the_last_oid_doesnt_exist()
    {
        $this->beConstructedWith(...[]);

        $this->last()->shouldBeNull();
    }

    function it_should_get_an_array_of_oids()
    {
        $this->toArray()->shouldBeLike([
            new Oid('5.4.3.2.1'),
        ]);
    }

    function it_should_get_the_oid_count()
    {
        $this->count()->shouldBeEqualTo(1);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequenceOf(
            (new Oid('5.4.3.2.1'))->toAsn1()
        ));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $this::fromAsn1(Asn1::sequenceOf((new Oid('5.4.3.2.1'))->toAsn1()))->shouldBeLike(
            new OidList(new Oid('5.4.3.2.1'))
        );
    }
}
