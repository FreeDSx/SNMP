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

use FreeDSx\Snmp\Exception\RediscoveryNeededException;
use FreeDSx\Snmp\Exception\SecurityModelException;
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
    /**
     * Handle any logic needed for processing an incoming message.
     *
     * @param AbstractMessageV3 $message
     * @param array $options
     * @return AbstractMessageV3
     * @throws RediscoveryNeededException
     * @throws SecurityModelException
     */
    public function handleIncomingMessage(AbstractMessageV3 $message, array $options) : AbstractMessageV3;

    /**
     * Handle any logic needed for processing an outgoing message.
     *
     * @param AbstractMessageV3 $message
     * @param array $options
     * @return AbstractMessageV3
     * @throws RediscoveryNeededException
     * @throws SecurityModelException
     */
    public function handleOutgoingMessage(AbstractMessageV3 $message, array $options) : AbstractMessageV3;

    /**
     * Get the discovery request to send. The response is handled separately.
     *
     * @param AbstractMessageV3 $messageV3
     * @param array $options
     * @return MessageRequestInterface|null
     */
    public function getDiscoveryRequest(AbstractMessageV3 $messageV3, array $options) : MessageRequestInterface;

    /**
     * Given the current message and options, determine if a discovery is needed.
     *
     * @param AbstractMessageV3 $messageV3
     * @param array $options
     * @return bool
     */
    public function isDiscoveryRequestNeeded(AbstractMessageV3 $messageV3, array $options) : bool;

    /**
     * Generate a needed discovery response given the request.
     *
     * @param AbstractMessageV3 $messageV3
     * @param array $options
     * @return MessageResponseInterface
     */
    public function getDiscoveryResponse(AbstractMessageV3 $messageV3, array $options) : MessageResponseInterface;

    /**
     * Given the message, determine if a discovery response needs to be sent.
     *
     * @param AbstractMessageV3 $messageV3
     * @param array $options
     * @return bool
     */
    public function isDiscoveryResponseNeeded(AbstractMessageV3 $messageV3, array $options) : bool;

    /**
     * When the discovery response is returned it will be passed here for any specific module processing.
     *
     * @param AbstractMessageV3 $message
     * @param MessageResponseInterface $discoveryResponse
     * @param array $options
     * @return AbstractMessageV3
     */
    public function handleDiscoveryResponse(AbstractMessageV3 $message, MessageResponseInterface $discoveryResponse, array $options) : AbstractMessageV3;

    /**
     * The security model that the module supports.
     *
     * @return int
     */
    public static function supports() : int;
}
