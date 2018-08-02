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

use FreeDSx\Snmp\Response\Response;
use FreeDSx\Snmp\Response\ResponseInterface;

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
     * @return ResponseInterface|Response
     */
    public function getResponse() : ResponseInterface;
}
