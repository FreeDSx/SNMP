<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Module\Authentication;

use FreeDSx\Snmp\Exception\SnmpAuthenticationException;
use FreeDSx\Snmp\Message\AbstractMessageV3;

/**
 * RFC 3414, Section 1.6.1.
 *
 * Represents the needed methods for an authentication module.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AuthenticationModuleInterface
{
    /**
     * Authenticate an incoming message according to an algorithm.
     *
     * @param AbstractMessageV3 $message
     * @param string $password
     * @throws SnmpAuthenticationException
     * @return mixed
     */
    public function authenticateIncomingMsg(AbstractMessageV3 $message, string $password) : AbstractMessageV3;


    /**
     * Authenticate an outgoing message according to an algorithm.
     *
     * @param AbstractMessageV3 $message
     * @param string $password
     * @throws SnmpAuthenticationException
     * @return mixed
     */
    public function authenticateOutgoingMsg(AbstractMessageV3 $message, string $password) : AbstractMessageV3;

    /**
     * @param string $password
     * @param string $engineId
     * @return string
     */
    public function generateKey(string $password, string $engineId);

    /**
     * @param $value
     * @return string
     */
    public function hash($value);

    /**
     * Get the algorithms supported as an array of string names.
     *
     * @return string[]
     */
    public static function supports() : array;
}
