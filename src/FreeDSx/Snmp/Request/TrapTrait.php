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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Value\OidValue;
use FreeDSx\Snmp\Value\TimeTicksValue;

/**
 * Represents common aspects of an SNMP v2 request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait TrapTrait
{
    /**
     * @var string
     */
    protected static $oidSysUpTime = '1.3.6.1.2.1.1.3.0';

    /**
     * @var string
     */
    protected static $oidTrap = '1.3.6.1.6.3.1.1.4.1.0';

    /**
     * @var TimeTicksValue
     */
    protected $sysUpTime;

    /**
     * @var OidValue
     */
    protected $trapOid;

    /**
     * @param TimeTicksValue $sysUpTime
     * @param OidValue $trapOid
     * @param null|OidList $oids
     */
    public function __construct(TimeTicksValue $sysUpTime, OidValue $trapOid, ?OidList $oids = null)
    {
        $this->sysUpTime = $sysUpTime;
        $this->trapOid = $trapOid;
        parent::__construct(0, 0, 0, ($oids ?: new OidList()));
    }

    /**
     * @return TimeTicksValue
     */
    public function getSysUpTime() : TimeTicksValue
    {
        return $this->sysUpTime;
    }

    /**
     * @return OidValue
     */
    public function getTrapOid() : OidValue
    {
        return $this->trapOid;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        list($id, $errorStatus, $errorIndex, $oidList) = parent::getBaseElements($type);

        /** @var OidList $oidList */
        if (\count($oidList->toArray()) < 2) {
            throw new ProtocolException('The trap is malformed. It must have at least 2 VarBind values.');
        }
        $sysUpTime = $oidList->index(1);
        if (!($sysUpTime->getOid() === self::$oidSysUpTime && $sysUpTime->getValue() instanceof TimeTicksValue)) {
            throw new ProtocolException('The trap is malformed. The first OID must be the sysUpTime.');
        }
        $trapOid = $oidList->index(2);
        if (!($trapOid->getOid() === self::$oidTrap && $trapOid->getValue() instanceof OidValue)) {
            throw new ProtocolException('The trap is malformed. The second OID must be the trap OID.');
        }
        $trapRequest = new self(
            $sysUpTime->getValue(),
            $trapOid->getValue(),
            new OidList(...\array_slice($oidList->toArray(), 2))
        );
        $trapRequest->id = $id;
        $trapRequest->errorStatus = $errorStatus;
        $trapRequest->errorIndex = $errorIndex;

        return $trapRequest;
    }

    /**
     * @param OidList $oidList
     * @return AbstractType
     */
    protected function oidListToAsn1(OidList $oidList): AbstractType
    {
        $trapOidList = new OidList(
            new Oid(self::$oidSysUpTime, $this->sysUpTime),
            new Oid(self::$oidTrap, $this->trapOid),
            ...$oidList->toArray()
        );

        return parent::oidListToAsn1($trapOidList);
    }
}
