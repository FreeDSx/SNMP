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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\NullType;
use FreeDSx\Asn1\Type\OidType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Value\AbstractValue;
use FreeDSx\Snmp\Protocol\Factory\OidValueFactory;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Protocol\SnmpEncoder;

/**
 * Represents a VarBind structure. RFC 3416 Section 3.
 *
 * VarBind ::= SEQUENCE {
 *     name ObjectName,
 *
 *     CHOICE {
 *         value          ObjectSyntax,
 *         unSpecified    NULL,    -- in retrieval requests
 *
 *                                 -- exceptions in responses
 *         noSuchObject   [0] IMPLICIT NULL,
 *         noSuchInstance [1] IMPLICIT NULL,
 *         endOfMibView   [2] IMPLICIT NULL
 *     }
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Oid implements ProtocolElementInterface
{
    public const STATUS_NO_SUCH_OBJECT = 0;

    public const STATUS_NO_SUCH_INSTANCE = 1;

    public const STATUS_END_OF_MIB_VIEW = 2;

    /**
     * @var string
     */
    protected $oid;

    /**
     * @var AbstractValue|null
     */
    protected $value;

    /**
     * @var int|null
     */
    protected $status;

    /**
     * @param string $oid
     * @param AbstractValue|null $value
     * @param int|null $status
     */
    public function __construct(string $oid, ?AbstractValue $value = null, ?int $status = null)
    {
        $this->oid = $oid;
        $this->value = $value;
        $this->status = $status;
    }

    /**
     * @return string
     */
    public function getOid() : string
    {
        return $this->oid;
    }

    /**
     * @param string $oid
     * @return $this
     */
    public function setOid(string $oid)
    {
        $this->oid = $oid;

        return $this;
    }

    /**
     * @return AbstractValue|null
     */
    public function getValue() : ?AbstractValue
    {
        return $this->value;
    }

    /**
     * @param AbstractValue|null $value
     * @return $this
     */
    public function setValue(?AbstractValue $value)
    {
        $this->value = $value;

        return $this;
    }

    /**
     * @return int|null
     */
    public function getStatus() : ?int
    {
        return $this->status;
    }

    /**
     * @param int|null $status
     * @return $this
     */
    public function setStatus(?int $status)
    {
        $this->status = $status;

        return $this;
    }

    /**
     * @param int|null $status
     * @return bool
     */
    public function hasStatus(?int $status = null) : bool
    {
        return $this->status === $status;
    }

    /**
     * @return bool
     */
    public function isEndOfMibView() : bool
    {
        return $this->status === self::STATUS_END_OF_MIB_VIEW;
    }

    /**
     * @return bool
     */
    public function isNoSuchObject() : bool
    {
        return $this->status === self::STATUS_NO_SUCH_OBJECT;
    }

    /**
     * @return bool
     */
    public function isNoSuchInstance() : bool
    {
        return $this->status === self::STATUS_NO_SUCH_INSTANCE;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        # It's common to represent OIDs with a leading dot. However, this is irrelevant to the ASN.1 BER representation.
        # This is a convenience to detect and strip a leading dot if used.
        $varBind = Asn1::sequence(Asn1::oid($this->oid[0] === '.' ? \substr($this->oid, 1) : $this->oid));

        if ($this->value === null && $this->status === null) {
            $varBind->addChild(Asn1::null());
        } elseif ($this->status !== null) {
            $varBind->addChild(Asn1::context($this->status, Asn1::null()));
        } else {
            $varBind->addChild($this->value->toAsn1());
        }

        return $varBind;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->oid;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $varBind)
    {
        if (!($varBind instanceof SequenceType && \count($varBind->getChildren()) >= 1)) {
            throw new ProtocolException('The Oid format is invalid.');
        }
        $oidName = $varBind->getChild(0);
        if (!$oidName instanceof OidType) {
            throw new ProtocolException('The Oid format is invalid.');
        }

        $status = null;
        $varBindValue = $varBind->getChild(1);
        if ($varBindValue instanceof NullType) {
            $varBindValue = null;
        } elseif ($varBindValue->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
            $varBindValue = (new SnmpEncoder())->complete($varBindValue, AbstractType::TAG_TYPE_NULL);
            switch ($varBindValue->getTagNumber()) {
                case self::STATUS_NO_SUCH_OBJECT:
                    $status = self::STATUS_NO_SUCH_OBJECT;
                    break;
                case self::STATUS_NO_SUCH_INSTANCE:
                    $status = Oid::STATUS_NO_SUCH_INSTANCE;
                    break;
                case self::STATUS_END_OF_MIB_VIEW:
                    $status = Oid::STATUS_END_OF_MIB_VIEW;
                    break;
                default:
                    throw new ProtocolException(sprintf(
                        'Oid status tag %s for Oid value not recognized.',
                        $varBindValue->getTagNumber()
                    ));
            }
            $varBindValue = null;
        } else {
            $varBindValue = OidValueFactory::get($varBindValue);
        }

        return new self(
            $oidName->getValue(),
            $varBindValue,
            $status
        );
    }

    /**
     * @param string $oid
     * @param string $ipAddress
     * @return Oid
     */
    public static function fromIpAddress(string $oid, string $ipAddress) : Oid
    {
        return new self($oid, OidValues::ipAddress($ipAddress));
    }

    /**
     * @param string $oid
     * @param int $value
     * @return Oid
     */
    public static function fromInteger(string $oid, int $value) : Oid
    {
        return new self($oid, OidValues::integer($value));
    }

    /**
     * @param string $oid
     * @param string $value
     * @return Oid
     */
    public static function fromOid(string $oid, string $value) : Oid
    {
        return new self($oid, OidValues::oid($value));
    }

    /**
     * @param string $oid
     * @param int $counter
     * @return Oid
     */
    public static function fromCounter(string $oid, int $counter) : Oid
    {
        return new self($oid, OidValues::counter($counter));
    }

    /**
     * @param int|string $counter
     */
    public static function fromBigCounter(string $oid, $counter) : Oid
    {
        return new self($oid, OidValues::bigCounter($counter));
    }

    /**
     * @param string $oid
     * @param int $timeticks
     * @return Oid
     */
    public static function fromTimeticks(string $oid, int $timeticks) : Oid
    {
        return new self($oid, OidValues::timeticks($timeticks));
    }

    /**
     * @param string $oid
     * @param int $value
     * @return Oid
     */
    public static function fromUnsignedInt(string $oid, int $value) : Oid
    {
        return new self($oid, OidValues::unsignedInteger($value));
    }

    /**
     * @param string $oid
     * @param string $value
     * @return Oid
     */
    public static function fromString(string $oid, string $value) : Oid
    {
        return new self($oid, OidValues::string($value));
    }
}
