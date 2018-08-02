<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message\Security;

use FreeDSx\Snmp\Protocol\ProtocolElementInterface;

/**
 * Implements the Security Parameter portion of the SNMPv3 Message.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SecurityParametersInterface extends ProtocolElementInterface
{
    /**
     * Represents the msgSecurityModel to be used in the header.
     *
     * @return int
     */
    public function getSecurityModel() : int;
}
