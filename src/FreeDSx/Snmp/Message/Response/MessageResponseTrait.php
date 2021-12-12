<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message\Response;

use FreeDSx\Snmp\Message\Pdu;

/**
 * Used to implement the message response interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait MessageResponseTrait
{
    /**
     * @return Pdu
     */
    public function getResponse() : Pdu
    {
        return $this->pdu;
    }
}
