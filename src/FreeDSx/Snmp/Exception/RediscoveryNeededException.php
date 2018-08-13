<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Exception;

/**
 * Thrown from the security model module if a rediscovery is needed at a point other than the initial discovery check.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RediscoveryNeededException extends SnmpRequestException
{
}
