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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Snmp\Exception\ProtocolException;

/**
 * Represents an IP address value (from network byte order).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class IpAddressValue extends AbstractValue
{
    protected const ASN1_TYPE = AbstractType::TAG_TYPE_OCTET_STRING;

    protected const ASN1_TAG = 0;

    protected const ASN1_CLASS = OctetStringType::class;

    /**
     * @param string $value
     */
    public function __construct(string $value)
    {
        $this->value = $value;
    }

    public function setValue(string $value) : void
    {
        $this->value = $value;
    }

    /**
     * @return string
     */
    public function getValue() : string
    {
        return $this->value;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        return Asn1::application(
            self::ASN1_TAG,
            Asn1::octetString(\pack('N', \ip2long($this->value)))
        );
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $ip = parent::fromAsn1($type);

        $value = @\unpack("Nip", $ip->value);
        if (!isset($value['ip'])) {
            throw new ProtocolException('Unable to parse IP address value.');
        }
        $ip->value = \long2ip($value['ip']);

        return $ip;
    }
}
