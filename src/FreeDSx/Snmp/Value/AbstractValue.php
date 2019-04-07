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
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Protocol\SnmpEncoder;

/**
 * A base OID value / string representation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class AbstractValue implements ProtocolElementInterface
{
    protected const ASN1_TYPE = null;

    protected const ASN1_TAG = null;

    protected const ASN1_CLASS = null;

    /**
     * @var mixed
     */
    protected $value;

    /**
     * @param mixed $value
     */
    public function equals($value, bool $strict = true) : bool
    {
        if ($strict) {
            return $this->value === $value;
        }

        return $this->value == $value;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return (string) $this->value;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        $typeClass = static::ASN1_CLASS;

        return Asn1::application(
            static::ASN1_TAG,
            new $typeClass($this->value)
        );
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        if (static::ASN1_TAG !== null && $type->getTagNumber() !== static::ASN1_TAG) {
            throw new ProtocolException(sprintf(
                'Expected tag number %s for class "%s". Got %s.',
                static::ASN1_TAG,
                static::class,
                $type->getTagNumber
            ));
        }

        return new static(
            (new SnmpEncoder())
                ->complete($type, static::ASN1_TYPE)
                ->getValue()
        );
    }
}
