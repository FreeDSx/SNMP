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

use FreeDSx\Snmp\Protocol\ProtocolElementInterface;

/**
 * Interface that SNMP requests must implement.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RequestInterface extends ProtocolElementInterface
{
    /**
     * @return int
     */
    public function getPduTag() : int;
}
