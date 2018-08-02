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
 * Represents an Inform Request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class InformRequest extends Pdu implements RequestInterface
{
    use TrapTrait,
        RequestTrait;

    protected const TAG = 6;
}
