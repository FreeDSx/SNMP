<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Module\SecurityModel;

use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;

/**
 * Represents the methods needed to handle a security model.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SecurityModelModuleInterface
{
    public function handleIncomingMessage(AbstractMessageV3 $message, array $options) : AbstractMessageV3;

    public function handleOutgoingMessage(AbstractMessageV3 $message, array $options) : AbstractMessageV3;

    public function getDiscoveryRequest(AbstractMessageV3 $messageV3, array $options) : ?MessageRequestInterface;

    public function handleDiscoveryResponse(AbstractMessageV3 $message, MessageResponseInterface $discoveryResponse, array $options) : AbstractMessageV3;

    public static function supports() : int;
}
