<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Module\Privacy;

use FreeDSx\Snmp\Exception\SnmpEncryptionException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModuleInterface;

/**
 * RFC 3414, Section 1.6.2.
 *
 * Represents the needed methods for a privacy module.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PrivacyModuleInterface
{
    /**
     * Decrypt message data according to the algorithm.
     *
     * @param AbstractMessageV3 $message
     * @param AuthenticationModuleInterface $authMod
     * @param string $privPwd
     * @throws SnmpEncryptionException
     */
    public function decryptData(AbstractMessageV3 $message, AuthenticationModuleInterface $authMod, string $privPwd) : void;

    /**
     * Encrypt message data according to the algorithm.
     *
     * @param MessageResponseV3|MessageRequestV3 $message
     * @param AuthenticationModuleInterface $authMod
     * @param string $privPwd
     * @throws SnmpEncryptionException
     */
    public function encryptData($message, AuthenticationModuleInterface $authMod, string $privPwd) : void;

    /**
     * Get the supported mechanisms of the module as an array of strings.
     *
     * @return string[]
     */
    public static function supports() : array;
}
