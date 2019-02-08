<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;

/**
 * Represents SNMPv3 Message Header data. RFC 3412.
 *
 * HeaderData ::= SEQUENCE {
 *     msgID      INTEGER (0..2147483647),
 *     msgMaxSize INTEGER (484..2147483647),
 *
 *     msgFlags   OCTET STRING (SIZE(1)),
 *                --  .... ...1   authFlag
 *                --  .... ..1.   privFlag
 *                --  .... .1..   reportableFlag
 *                --              Please observe:
 *                --  .... ..00   is OK, means noAuthNoPriv
 *                --  .... ..01   is OK, means authNoPriv
 *                --  .... ..10   reserved, MUST NOT be used.
 *                --  .... ..11   is OK, means authPriv
 *
 *     msgSecurityModel INTEGER (1..2147483647)
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageHeader implements ProtocolElementInterface
{
    public const FLAG_NO_AUTH_NO_PRIV = 0;

    public const FLAG_AUTH = 1;

    public const FLAG_PRIV = 2;

    public const FLAG_REPORTABLE = 4;

    public const FLAG_AUTH_PRIV = self::FLAG_AUTH | self::FLAG_PRIV;

    protected const FLAGS = [
        self::FLAG_AUTH,
        self::FLAG_PRIV,
        self::FLAG_REPORTABLE,
    ];

    /**
     * @var int
     */
    protected $id;

    /**
     * @var int
     */
    protected $maxSize;

    /**
     * @var int
     */
    protected $flags;

    /**
     * @var int
     */
    protected $securityModel;

    /**
     * @param int $id
     * @param int $maxSize
     * @param int $flags
     * @param int $securityModel
     */
    public function __construct(int $id, int $flags = self::FLAG_NO_AUTH_NO_PRIV, int $securityModel = 3, int $maxSize = 65507)
    {
        $this->id = $id;
        $this->flags = $flags;
        $this->securityModel = $securityModel;
        $this->maxSize = $maxSize;
    }

    /**
     * @param int $flag
     * @return $this
     */
    public function addFlag(int $flag)
    {
        if ($this->hasFlag($flag)) {
            return $this;
        }
        if ($flag === 0) {
            $this->flags = 0;

            return $this;
        }
        if (!\in_array($flag, self::FLAGS)) {
            throw new InvalidArgumentException(sprintf(
                'The flag %s is not valid.',
                $flag
            ));
        }
        $this->flags |= $flag;

        return $this;
    }

    /**
     * @param int $flag
     * @return bool
     */
    public function hasFlag(int $flag) : bool
    {
        if ($flag === 0) {
            return $this->flags === $flag;
        }

        return ($this->flags !== 0 && $this->flags & $flag);
    }

    /**
     * @return bool
     */
    public function hasAuthentication() : bool
    {
        return $this->hasFlag(self::FLAG_AUTH);
    }

    /**
     * @return bool
     */
    public function hasPrivacy() : bool
    {
        return $this->hasFlag(self::FLAG_PRIV);
    }

    /**
     * @return bool
     */
    public function isReportable() : bool
    {
        return $this->hasFlag(self::FLAG_REPORTABLE);
    }

    /**
     * @return int
     */
    public function getFlags() : int
    {
        return $this->flags;
    }

    /**
     * @param int $flags
     * @return MessageHeader
     */
    public function setFlags(int $flags)
    {
        $this->flags = $flags;

        return $this;
    }

    /**
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * @param int $id
     * @return MessageHeader
     */
    public function setId(int $id)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * @return int
     */
    public function getMaxSize() : int
    {
        return $this->maxSize;
    }

    /**
     * @param int $maxSize
     * @return MessageHeader
     */
    public function setMaxSize(int $maxSize)
    {
        $this->maxSize = $maxSize;

        return $this;
    }

    /**
     * @return int
     */
    public function getSecurityModel() : int
    {
        return $this->securityModel;
    }

    /**
     * @param int $securityModel
     * @return MessageHeader
     */
    public function setSecurityModel(int $securityModel)
    {
        $this->securityModel = $securityModel;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        return Asn1::sequence(
            Asn1::integer($this->id),
            Asn1::integer($this->maxSize),
            Asn1::octetString(\chr($this->flags)),
            Asn1::integer($this->securityModel)
        );
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        if (!$type instanceof SequenceType && \count($type->getChildren()) !== 4) {
            throw new ProtocolException('The message header must be a sequence with 4 elements.');
        }
        $id = $type->getChild(0);
        $maxSize = $type->getChild(1);
        $flags = $type->getChild(2);
        $securityModel = $type->getChild(3);

        if (!$id instanceof IntegerType) {
            throw new ProtocolException('The header ID must be an integer type.');
        }
        if (!$maxSize instanceof IntegerType && $maxSize->getValue() >= 484) {
            throw new ProtocolException('The maxSize must be an integer type greater than or equal to 484.');
        }
        if (!$flags instanceof OctetStringType && strlen($flags->getValue()) === 1) {
            throw new ProtocolException('The flags must be an octet string type with one byte.');
        }
        if (!$securityModel instanceof IntegerType) {
            throw new ProtocolException('The securityModel must be an integer type.');
        }

        return new self(
            $id->getValue(),
            ord($flags->getValue()),
            $securityModel->getValue(),
            $maxSize->getValue()
        );
    }
}
