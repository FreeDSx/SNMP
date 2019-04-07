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

use FreeDSx\Snmp\Request\GetBulkRequest;
use FreeDSx\Snmp\Request\GetNextRequest;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\SetRequest;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Value\IpAddressValue;
use FreeDSx\Snmp\Value\OidValue;
use FreeDSx\Snmp\Value\TimeTicksValue;

/**
 * Factory methods for generating requests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Requests
{
    /**
     * @param int $maxRepetitions
     * @param int $nonRepeaters
     * @param mixed ...$oids
     * @return GetBulkRequest
     */
    public static function getBulk(int $maxRepetitions, int $nonRepeaters, ...$oids) : GetBulkRequest
    {
        return new GetBulkRequest($maxRepetitions, $nonRepeaters, self::toOidList($oids));
    }

    /**
     * @param mixed ...$oids
     * @return GetRequest
     */
    public static function get(...$oids) : GetRequest
    {
        return new GetRequest(self::toOidList($oids));
    }

    /**
     * @param mixed ...$oids
     * @return GetNextRequest
     */
    public static function getNext(...$oids) : GetNextRequest
    {
        return new GetNextRequest(self::toOidList($oids));
    }

    /**
     * @param mixed ...$oids
     * @return SetRequest
     */
    public static function set(...$oids) : SetRequest
    {
        return new SetRequest(self::toOidList($oids));
    }

    /**
     * @param int|TimeTicksValue $sysUpTime
     * @param string|OidValue $trapOid
     * @param mixed ...$oids
     * @return TrapV2Request
     */
    public static function trap($sysUpTime, $trapOid, ...$oids) : TrapV2Request
    {
        list('oids' => $oids, 'sysUpTime' => $sysUpTime, 'trapOid' => $trapOid) = self::toTrapArgs(
            $sysUpTime,
            $trapOid,
            $oids
        );

        return new TrapV2Request($sysUpTime, $trapOid, $oids);
    }

    /**
     * @param string $enterprise
     * @param string|IpAddressValue $ipAddress
     * @param int $genericType
     * @param int $specificType
     * @param int|TimeTicksValue $sysUpTime
     * @param mixed ...$oids
     * @return TrapV1Request
     */
    public static function trapV1(string $enterprise, $ipAddress, int $genericType, int $specificType, int $sysUpTime, ...$oids) : TrapV1Request
    {
        $ipAddress = ($ipAddress instanceof IpAddressValue) ? $ipAddress : OidValues::ipAddress($ipAddress);
        $sysUpTime = ($sysUpTime instanceof TimeTicksValue) ? $sysUpTime : OidValues::timeticks($sysUpTime);

        return new TrapV1Request($enterprise, $ipAddress, $genericType, $specificType, $sysUpTime, self::toOidList($oids));
    }

    /**
     * @param int|TimeTicksValue $sysUpTime
     * @param string|OidValue $trapOid
     * @param mixed ...$oids
     * @return InformRequest
     */
    public static function inform($sysUpTime, $trapOid, ...$oids) : InformRequest
    {
        list('oids' => $oids, 'sysUpTime' => $sysUpTime, 'trapOid' => $trapOid) = self::toTrapArgs(
            $sysUpTime,
            $trapOid,
            $oids
        );

        return new InformRequest($sysUpTime, $trapOid, $oids);
    }

    /**
     * @param TimeTicksValue|mixed $sysUpTime
     * @param OidValue|mixed $trapOid
     * @param Oid[]|string[] $oids
     * @return mixed[]
     */
    protected static function toTrapArgs($sysUpTime, $trapOid, $oids) : array
    {
        $sysUpTime = ($sysUpTime instanceof TimeTicksValue) ? $sysUpTime : new TimeTicksValue((int) $sysUpTime);
        $trapOid = ($trapOid instanceof OidValue) ? $trapOid : new OidValue((string)$trapOid);

        return ['sysUpTime' => $sysUpTime, 'trapOid' => $trapOid, 'oids' => self::toOidList($oids)];
    }

    /**
     * @param array $oids
     * @return OidList
     */
    protected static function toOidList(array $oids) : OidList
    {
        $oidList = [];

        foreach ($oids as $oid) {
            if ($oid instanceof Oid) {
                $oidList[] = $oid;
            } else {
                $oidList[] = new Oid($oid);
            }
        }

        return new OidList(...$oidList);
    }
}
