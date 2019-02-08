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
use FreeDSx\Snmp\Exception\InvalidArgumentException;

/**
 * Represents a big counter value.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BigCounterValue extends AbstractValue
{
    protected const ASN1_TYPE = AbstractType::TAG_TYPE_INTEGER;

    protected const ASN1_TAG = 6;

    protected const ASN1_CLASS = IntegerType::class;

    /**
     * @param int $value
     */
    public function __construct($value)
    {
        $this->validate($value);
        $this->value = $value;
    }

    /**
     * @return string|int
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param int $value
     * @return BigCounterValue
     */
    public function setValue($value)
    {
        $this->validate($value);
        $this->value = $value;

        return $this;
    }

    /**
     * Whether or not the contained value is larger than the PHP_INT_MAX value (represented as a string value).
     *
     * @return bool
     */
    public function isBigInt() : bool
    {
        if (\is_int($this->value)) {
            return false;
        }

        return \is_float($this->value + 0);
    }

    /**
     * @param $integer
     */
    protected function validate($integer) : void
    {
        if (\is_int($integer)) {
            return;
        }
        if (\is_string($integer) && \is_numeric($integer) && \strpos($integer, '.') === false) {
            return;
        }

        throw new InvalidArgumentException('The value passed to the BigCounter class must be numeric.');
    }
}
