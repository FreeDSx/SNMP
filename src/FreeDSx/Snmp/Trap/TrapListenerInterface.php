<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Trap;

use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Module\SecurityModel\Usm\UsmUser;

/**
 * Interface used in the trap sink to act on received traps.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface TrapListenerInterface
{
    /**
     * Whether or not the host should be accepted. Return true to allow the trap, return false to deny it.
     *
     * @param string $ip
     * @return bool
     */
    public function accept(string $ip) : bool;

    /**
     * Given an engineId/IP address, get the USM user information associated with it. This information is used to potentially
     * authenticate and/or decrypt an incoming SNMP v3 trap using the USM security model.
     *
     * To ignore a request by a specific engine ID and user, return null.
     *
     * @param EngineId $engineId
     * @param string $ipAddress
     * @param string $user
     * @return UsmUser
     */
    public function getUsmUser(EngineId $engineId, string $ipAddress, string $user) : ?UsmUser;

    /**
     * Handle a received trap.
     *
     * @param TrapContext $context
     */
    public function receive(TrapContext $context) : void;
}
