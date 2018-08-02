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
use FreeDSx\Asn1\Type\OidType;
use FreeDSx\Snmp\Exception\ProtocolException;

/**
 * Represents a simple OID value.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OidValue extends AbstractValue
{
    /**
     * @param string $value
     */
    public function __construct(string $value)
    {
        $this->value = $value;
    }

    /**
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }

    /**
     * @param string $value
     * @return OidValue
     */
    public function setValue(string $value)
    {
        $this->value = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        return Asn1::oid($this->value);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        if (!$type instanceof OidType) {
            throw new ProtocolException(sprintf(
                'The simple oid value must be an ASN.1 OID type. Got %s.',
                get_class($type)
            ));
        }

        return new self($type->getValue());
    }
}
