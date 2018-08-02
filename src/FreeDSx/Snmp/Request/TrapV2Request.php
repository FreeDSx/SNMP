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

use FreeDSx\Snmp\Message\Pdu;

/**
 * RFC 3416, Section 4.2.6. Represents an SNMP v2 trap.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TrapV2Request extends Pdu implements RequestInterface
{
    use TrapTrait,
        RequestTrait;

    protected const TAG = 7;
}
