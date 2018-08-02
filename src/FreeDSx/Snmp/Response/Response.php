<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Response;

use FreeDSx\Snmp\Message\Pdu;

/**
 * Represents an SNMP Response PDU.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Response extends Pdu implements ResponseInterface
{
    protected const TAG = 2;
}
