<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message\Request;

use FreeDSx\Snmp\Message\Pdu;

/**
 * Exposes the request PDU.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait MessageRequestTrait
{
    /**
     * @return Pdu
     */
    public function getRequest(): Pdu
    {
        return $this->pdu;
    }

    /**
     * @param Pdu $request
     * @return $this
     */
    public function setRequest(Pdu $request)
    {
        $this->pdu = $request;

        return $this;
    }
}
