<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Protocol\Factory;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\OidType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Value\AbstractValue;
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
 * Map a VarBind value to an OidValue type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OidValueFactory
{
    /**
     * @var array
     */
    protected static $appMap = [
        0 => IpAddressValue::class,
        1 => CounterValue::class,
        2 => UnsignedIntegerValue::class,
        3 => TimeTicksValue::class,
        4 => ArbitraryValue::class,
        6 => BigCounterValue::class,
    ];

    protected static $simpleMap = [
        IntegerType::class => IntegerValue::class,
        OctetStringType::class => StringValue::class,
        OidType::class => OidValue::class,
    ];

    /**
     * @param AbstractType $type
     * @return AbstractValue
     * @throws ProtocolException
     */
    public static function get(AbstractType $type)
    {
        if (isset(self::$simpleMap[\get_class($type)])) {
            return \call_user_func(self::$simpleMap[\get_class($type)].'::fromAsn1', $type);
        } elseif ($type->getTagClass() === AbstractType::TAG_CLASS_APPLICATION && isset(self::$appMap[$type->getTagNumber()])) {
            return \call_user_func(self::$appMap[$type->getTagNumber()].'::fromAsn1', $type);
        } else {
            throw new ProtocolException(sprintf(
                'The SNMP VarBind value from ASN.1 type %s and tag %s is not recognized.',
                get_class($type),
                $type->getTagNumber()
            ));
        }
    }
}
