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
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Protocol\SnmpEncoder;

/**
 * Represents an SNMP PDU.
 *
 * PDU ::= SEQUENCE {
 *     request-id INTEGER (-214783648..214783647),
 *
 *     error-status                -- sometimes ignored
 *         INTEGER {
 *             noError(0),
 *             tooBig(1),
 *             noSuchName(2),      -- for proxy compatibility
 *             badValue(3),        -- for proxy compatibility
 *             readOnly(4),        -- for proxy compatibility
 *             genErr(5),
 *             noAccess(6),
 *             wrongType(7),
 *             wrongLength(8),
 *             wrongEncoding(9),
 *             wrongValue(10),
 *             noCreation(11),
 *             inconsistentValue(12),
 *             resourceUnavailable(13),
 *             commitFailed(14),
 *             undoFailed(15),
 *             authorizationError(16),
 *             notWritable(17),
 *             inconsistentName(18)
 *         },
 *
 *     error-index                 -- sometimes ignored
 *         INTEGER (0..max-bindings),
 *
 *     variable-bindings           -- values are sometimes ignored
 *         OidList
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Pdu implements ProtocolElementInterface
{
    protected const TAG = 0;

    /**
     * @var int
     */
    protected $id;

    /**
     * @var int
     */
    protected $errorStatus;

    /**
     * @var int
     */
    protected $errorIndex;

    /**
     * @var OidList
     */
    protected $oids;

    /**
     * @var bool
     */
    protected $includeValues = true;

    /**
     * @param int $id
     * @param int $errorStatus
     * @param int $errorIndex
     * @param OidList $oids
     */
    public function __construct(int $id, int $errorStatus = 0, int $errorIndex = 0, ?OidList $oids = null)
    {
        $this->id = $id;
        $this->errorStatus = $errorStatus;
        $this->errorIndex = $errorIndex;
        $this->oids = $oids ?:new OidList();
    }

    /**
     * @return int
     */
    public function getId() : int
    {
        return $this->id;
    }

    /**
     * @return int
     */
    public function getErrorStatus() : int
    {
        return $this->errorStatus;
    }

    /**
     * @return int
     */
    public function getErrorIndex() : int
    {
        return $this->errorIndex;
    }

    /**
     * @return OidList
     */
    public function getOids() : OidList
    {
        return $this->oids;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        return Asn1::context(static::getPduTag(), Asn1::sequence(
            Asn1::integer($this->id),
            Asn1::integer($this->errorStatus),
            Asn1::integer($this->errorIndex),
            $this->oidListToAsn1($this->oids)
        ));
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        return new static(...self::getBaseElements($type));
    }

    /**
     * @return int
     */
    public function getPduTag(): int
    {
        return static::TAG;
    }

    /**
     * @param OidList $oidList
     * @return AbstractType
     */
    protected function oidListToAsn1(OidList $oidList) : AbstractType
    {
        if ($this->includeValues) {
            $oids = $oidList->toAsn1();
        } else {
            $oids = [];
            foreach ($oidList as $oid) {
                $oids[] = new Oid($oid->getOid());
            }
            $oids = (new OidList(...$oids))->toAsn1();
        }

        return $oids;
    }

    /**
     * @param AbstractType $type
     * @return array
     * @throws ProtocolException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     */
    protected static function getBaseElements(AbstractType $type) : array
    {
        $type = (new SnmpEncoder())->complete($type, AbstractType::TAG_TYPE_SEQUENCE);
        if (\count($type->getChildren()) !== 4) {
            throw new ProtocolException('The PDU must be a sequence with 4 elements.');
        }
        $id = $type->getChild(0);
        $errorStatus = $type->getChild(1);
        $errorIndex = $type->getChild(2);
        $varBindList = $type->getChild(3);

        if (!$id instanceof IntegerType) {
            throw new ProtocolException('The PDU ID must be an integer.');
        }
        if (!$errorStatus instanceof IntegerType) {
            throw new ProtocolException('The PDU error status must be an integer.');
        }
        if (!$errorIndex instanceof IntegerType) {
            throw new ProtocolException('The PDU error index must be an integer.');
        }

        return [
            $id->getValue(),
            $errorStatus->getValue(),
            $errorIndex->getValue(),
            OidList::fromAsn1($varBindList)
        ];
    }
}
