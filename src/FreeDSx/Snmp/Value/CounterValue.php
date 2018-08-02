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
 * Represents an SNMP counter value.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CounterValue extends AbstractValue
{
    protected const ASN1_TYPE = AbstractType::TAG_TYPE_INTEGER;

    protected const ASN1_TAG = 1;

    protected const ASN1_CLASS = IntegerType::class;

    public function __construct(int $value)
    {
        $this->value = $value;
    }

    /**
     * @return int
     */
    public function getValue(): int
    {
        return $this->value;
    }

    /**
     * @param int $value
     */
    public function setValue(int $value): void
    {
        $this->value = $value;
    }
}
