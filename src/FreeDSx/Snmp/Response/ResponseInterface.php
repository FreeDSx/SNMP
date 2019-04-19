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

use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;

/**
 * Interface that SNMP responses must implement.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ResponseInterface extends ProtocolElementInterface
{
    public function getId() : int;

    public function getPduTag() : int;

    public function getErrorIndex() : int;

    public function getErrorStatus() : int;

    public function getOids() : OidList;
}
