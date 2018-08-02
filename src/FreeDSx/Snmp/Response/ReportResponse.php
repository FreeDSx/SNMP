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
 * Represents a report response. RFC 3416, Section 3.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ReportResponse extends Pdu implements ResponseInterface
{
    protected const TAG = 8;
}
