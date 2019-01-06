<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp;

use FreeDSx\Snmp\Value\ArbitraryValue;
use FreeDSx\Snmp\Value\BigCounterValue;
use FreeDSx\Snmp\Value\CounterValue;
use FreeDSx\Snmp\Value\IntegerValue;
use FreeDSx\Snmp\Value\IpAddressValue;
use FreeDSx\Snmp\Value\OidValue;
use FreeDSx\Snmp\Value\StringValue;
use FreeDSx\Snmp\Value\TimeTicksValue;
use FreeDSx\Snmp\Value\UnsignedIntegerValue;

/**
 * Factory methods to build OID values.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OidValues
{
    /**
     * @param $value
     * @return ArbitraryValue
     */
    public static function arbitrary($value) : ArbitraryValue
    {
        return new ArbitraryValue($value);
    }

    /**
     * @param int $value
     * @return IntegerValue
     */
    public static function integer(int $value) : IntegerValue
    {
        return new IntegerValue($value);
    }

    /**
     * @param string $value
     * @return StringValue
     */
    public static function string(string $value) : StringValue
    {
        return new StringValue($value);
    }

    /**
     * @param int|string $value
     * @return BigCounterValue
     */
    public static function bigCounter($value) : BigCounterValue
    {
        return new BigCounterValue($value);
    }

    /**
     * @param int $value
     * @return CounterValue
     */
    public static function counter(int $value) : CounterValue
    {
        return new CounterValue($value);
    }

    /**
     * @param string $value
     * @return IpAddressValue
     */
    public static function ipAddress(string $value) : IpAddressValue
    {
        return new IpAddressValue($value);
    }

    /**
     * @param int $value
     * @return TimeTicksValue
     */
    public static function timeticks(int $value) : TimeTicksValue
    {
        return new TimeTicksValue($value);
    }

    /**
     * @param int $value
     * @return UnsignedIntegerValue
     */
    public static function unsignedInteger(int $value) : UnsignedIntegerValue
    {
        return new UnsignedIntegerValue($value);
    }

    /**
     * @param string $oid
     * @return OidValue
     */
    public static function oid(string $oid) : OidValue
    {
        return new OidValue($oid);
    }
}
