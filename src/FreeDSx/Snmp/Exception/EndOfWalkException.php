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
 * Thrown if at the end of a SNMP walk but the next OID was requested.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class EndOfWalkException extends \Exception
{
}
