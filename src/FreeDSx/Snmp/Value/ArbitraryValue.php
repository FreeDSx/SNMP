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
use FreeDSx\Asn1\Type\OctetStringType;

/**
 * Represents an SNMP opaque value.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ArbitraryValue extends AbstractValue
{
    protected const ASN1_TYPE = AbstractType::TAG_TYPE_OCTET_STRING;

    protected const ASN1_TAG = 4;

    protected const ASN1_CLASS = OctetStringType::class;

    /**
     * @param mixed $value
     */
    public function __construct($value)
    {
        $this->value = $value;
    }

    /**
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param mixed $value
     * @return $this
     */
    public function setValue($value)
    {
        $this->value = $value;

        return $this;
    }
}
