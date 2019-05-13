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
use FreeDSx\Snmp\Request\RequestInterface;

/**
 * Exposes the request PDU.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait MessageRequestTrait
{
    public function getRequest() : RequestInterface
    {
        return $this->pdu;
    }

    /**
     * @return static
     */
    public function setRequest(RequestInterface $request) : self
    {
        $this->pdu = $request;

        return $this;
    }
}
