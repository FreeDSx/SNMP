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
 * Interface for an SNMP message used in a response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MessageResponseInterface
{
    /**
     * @return int
     */
    public function getVersion() : int;

    /**
     * @return Pdu
     */
    public function getResponse() : Pdu;
}
