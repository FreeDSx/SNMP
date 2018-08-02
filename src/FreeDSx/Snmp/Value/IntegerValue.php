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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Snmp\Exception\ProtocolException;

/**
 * Represents a simple integer type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class IntegerValue extends AbstractValue
{
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
    public function getValue(): int
    {
        return $this->value;
    }

    /**
     * @param int $value
     * @return IntegerValue
     */
    public function setValue(int $value)
    {
        $this->value = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        return Asn1::integer($this->value);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        if (!$type instanceof IntegerType) {
            throw new ProtocolException(sprintf(
               'The simple integer value must be an ASN.1 integer type. Got %s.',
               get_class($type)
            ));
        }

        return new self($type->getValue());
    }
}
