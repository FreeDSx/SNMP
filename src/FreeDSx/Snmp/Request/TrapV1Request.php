<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OidType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Value\IpAddressValue;
use FreeDSx\Snmp\Value\TimeTicksValue;
use FreeDSx\Snmp\Protocol\SnmpEncoder;

/**
 * The SNMP v1 Trap PDU. RFC 1157.
 *
 *      Trap-PDU ::=
 *          [4]
 *
 *              IMPLICIT SEQUENCE {
 *                  enterprise          -- type of object generating
 *                                      -- trap, see sysObjectID in [5]
 *                      OBJECT IDENTIFIER,
 *
 *                  agent-addr          -- address of object generating
 *                      NetworkAddress, -- trap
 *
 *                  generic-trap        -- generic trap type
 *                      INTEGER {
 *                          coldStart(0),
 *                          warmStart(1),
 *                          linkDown(2),
 *                          linkUp(3),
 *                          authenticationFailure(4),
 *                          egpNeighborLoss(5),
 *                          enterpriseSpecific(6)
 *                      },
 *
 *                  specific-trap     -- specific code, present even
 *                      INTEGER,      -- if generic-trap is not
 *                                    -- enterpriseSpecific
 *
 *                  time-stamp        -- time elapsed between the last
 *                    TimeTicks,      -- (re)initialization of the network
 *                                    -- entity and the generation of the
 *                                       trap
 *
 *                  variable-bindings   -- "interesting" information
 *                      VarBindList
 *              }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TrapV1Request implements RequestInterface
{
    use RequestTrait;

    public const GENERIC_COLD_START = 0;

    public const GENERIC_WARM_START = 1;

    public const GENERIC_LINK_DOWN = 2;

    public const GENERIC_LINK_UP = 3;

    public const GENERIC_AUTH_FAILURE = 4;

    public const GENERIC_EGP_NEIGHBOR_LOSS = 5;

    public const GENERIC_ENTERPRISE_SPECIFIC = 6;

    protected const TAG = 4;

    /**
     * @var string
     */
    protected $enterprise;

    /**
     * @var IpAddressValue
     */
    protected $ipAddress;

    /**
     * @var int
     */
    protected $genericType;

    /**
     * @var int
     */
    protected $specificType;

    /**
     * @var TimeTicksValue
     */
    protected $sysUpTime;

    /**
     * @var OidList
     */
    protected $oids;

    /**
     * @param string $enterprise
     * @param IpAddressValue $ipAddress
     * @param int $genericType
     * @param int $specificType
     * @param TimeTicksValue $sysUpTime
     * @param OidList $oids
     */
    public function __construct(string $enterprise, IpAddressValue $ipAddress, int $genericType, int $specificType, TimeTicksValue $sysUpTime, OidList $oids)
    {
        $this->enterprise = $enterprise;
        $this->ipAddress = $ipAddress;
        $this->genericType = $genericType;
        $this->specificType = $specificType;
        $this->sysUpTime = $sysUpTime;
        $this->oids = $oids;
    }

    /**
     * @return OidList
     */
    public function getOids() : OidList
    {
        return $this->oids;
    }

    /**
     * @param OidList $oids
     * @return $this
     */
    public function setOids(OidList $oids)
    {
        $this->oids = $oids;

        return $this;
    }

    /**
     * @return string
     */
    public function getIpAddress() : IpAddressValue
    {
        return $this->ipAddress;
    }

    /**
     * @param IpAddressValue $ipAddress
     * @return $this
     */
    public function setIpAddress(IpAddressValue $ipAddress)
    {
        $this->ipAddress = $ipAddress;

        return $this;
    }

    /**
     * @return string
     */
    public function getEnterprise() : string
    {
        return $this->enterprise;
    }

    /**
     * @param string $enterprise
     * @return $this
     */
    public function setEnterprise(string $enterprise)
    {
        $this->enterprise = $enterprise;

        return $this;
    }

    /**
     * @return int
     */
    public function getGenericType() : int
    {
        return $this->genericType;
    }

    /**
     * @param int $genericType
     * @return $this
     */
    public function setGenericType(int $genericType)
    {
        $this->genericType = $genericType;

        return $this;
    }

    /**
     * @return int
     */
    public function getSpecificType() : int
    {
        return $this->specificType;
    }

    /**
     * @param int $specificType
     * @return $this
     */
    public function setSpecificType(int $specificType)
    {
        $this->specificType = $specificType;

        return $this;
    }

    /**
     * @return TimeTicksValue
     */
    public function getSysUpTime() : TimeTicksValue
    {
        return $this->sysUpTime;
    }

    /**
     * @param TimeTicksValue $sysUpTime
     * @return $this
     */
    public function setSysUpTime(TimeTicksValue $sysUpTime)
    {
        $this->sysUpTime = $sysUpTime;

        return $this;
    }

    /**
     * @return int
     */
    public function getPduTag(): int
    {
        return self::TAG;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        return Asn1::context(self::TAG, Asn1::sequence(
            Asn1::oid($this->enterprise),
            $this->ipAddress->toAsn1(),
            Asn1::integer($this->genericType),
            Asn1::integer($this->specificType),
            $this->sysUpTime->toAsn1(),
            $this->oids->toAsn1()
        ));
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $trapPdu)
    {
        /** @var SequenceType $trapPdu */
        $trapPdu = (new SnmpEncoder())->complete($trapPdu, AbstractType::TAG_TYPE_SEQUENCE);

        $enterprise = $trapPdu->getChild(0);
        $ipAddress = $trapPdu->getChild(1);
        $genericType = $trapPdu->getChild(2);
        $specificType = $trapPdu->getChild(3);
        $sysUpTime = $trapPdu->getChild(4);
        $varBindList = $trapPdu->getChild(5);

        if (!$enterprise instanceof OidType) {
            throw new ProtocolException(sprintf(
               'The enterprise must be an Oid Type, got %s.',
               get_class($enterprise)
            ));
        }
        if (!$genericType instanceof IntegerType) {
            throw new ProtocolException(sprintf(
                'The generic trap type must be an Integer Type, got %s.',
                get_class($genericType)
            ));
        }
        if (!$specificType instanceof IntegerType) {
            throw new ProtocolException(sprintf(
                'The specific trap type must be an Integer Type, got %s.',
                get_class($specificType)
            ));
        }

        return new self(
            $enterprise->getValue(),
            IpAddressValue::fromAsn1($ipAddress),
            $genericType->getValue(),
            $specificType->getValue(),
            TimeTicksValue::fromAsn1($sysUpTime),
            OidList::fromAsn1($varBindList)
        );
    }
}
