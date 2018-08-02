<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Value;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;

/**
 * Represents an SNMP unsigned integer value.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class UnsignedIntegerValue extends AbstractValue
{
    protected const ASN1_TYPE = AbstractType::TAG_TYPE_INTEGER;

    protected const ASN1_TAG = 2;

    protected const ASN1_CLASS = IntegerType::class;

    /**
     * @param int $value
     */
    public function __construct(int $value)
    {
        $this->value = $value;
    }

    /**
     * @return int
     */
    public function getValue() : int
    {
        return $this->value;
    }

    /**
     * @param int $value
     * @return UnsignedIntegerValue
     */
    public function setValue(int $value)
    {
        $this->value = $value;

        return $this;
    }
}
