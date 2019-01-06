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

use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Value\ArbitraryValue;
use FreeDSx\Snmp\Value\BigCounterValue;
use FreeDSx\Snmp\Value\CounterValue;
use FreeDSx\Snmp\Value\IntegerValue;
use FreeDSx\Snmp\Value\IpAddressValue;
use FreeDSx\Snmp\Value\StringValue;
use FreeDSx\Snmp\Value\TimeTicksValue;
use FreeDSx\Snmp\Value\UnsignedIntegerValue;
use PhpSpec\ObjectBehavior;

class OidValuesSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(OidValues::class);
    }

    function it_should_get_an_arbitrary_value()
    {
        $this::arbitrary('foo')->shouldBeLike(new ArbitraryValue('foo'));
    }

    function it_should_get_an_integer_value()
    {
        $this::integer(1)->shouldBeLike(new IntegerValue(1));
    }

    function it_should_get_a_string_value()
    {
        $this::string('foo')->shouldBeLike(new StringValue('foo'));
    }

    function it_should_get_a_big_counter_value()
    {
        $this::bigCounter(1)->shouldBeLike(new BigCounterValue(1));
    }

    function it_should_get_a_big_counter_value_with_a_numeric_string()
    {
        $this::bigCounter('123456789')->shouldBeLike(new BigCounterValue('123456789'));
    }

    function it_should_get_a_counter_value()
    {
        $this::counter(1)->shouldBeLike(new CounterValue(1));
    }

    function it_should_get_an_ip_address_value()
    {
        $this::ipAddress('127.0.0.1')->shouldBeLike(new IpAddressValue('127.0.0.1'));
    }

    function it_should_get_a_timeticks_value()
    {
        $this::timeticks(1)->shouldBeLike(new TimeTicksValue(1));
    }

    function it_should_get_an_unsigned_int_value()
    {
        $this::unsignedInteger(2)->shouldBeLike(new UnsignedIntegerValue(2));
    }
}
