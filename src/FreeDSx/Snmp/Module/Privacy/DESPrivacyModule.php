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

use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModuleInterface;

/**
 * RFC 3414
 *
 * DES privacy mechanisms for encrypting / decrypting the ScopedPDU.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
*/
class DESPrivacyModule implements PrivacyModuleInterface
{
    use PrivacyTrait,
        DESPrivacyTrait;

    protected const ALIASES = [
        'des' => 'des-cbc',
    ];

    protected const ALGORITHMS = [
        'des',
        'des-cbc',
    ];

    /**
     * {@inheritdoc}
     */
    public static function supports() : array
    {
        return self::ALGORITHMS;
    }

    /**
     * {@inheritdoc}
     */
    protected function toKeySaltIV($cryptKey, UsmSecurityParameters $usm, AuthenticationModuleInterface $authMod, $salt = null) : array
    {
        # The first 8 octets of the 16-octet secret (private privacy key) are
        # used as a DES key.  Since DES uses only 56 bits, the Least
        # Significant Bit in each octet is disregarded.
        $key = \substr($cryptKey, 0, 8);
        # The last 8 octets of the 16-octet secret (private privacy key) are used as pre-IV.
        $preIV = \substr($cryptKey, 8, 8);

        # The 32-bit snmpEngineBoots is converted to the first 4 octets (Most
        # Significant Byte first) of our "salt".  The 32-bit integer is then
        # converted to the last 4 octet (Most Significant Byte first) of our
        # "salt".
        if ($salt === null) {
            $salt = $this->intToSaltBytes($usm->getEngineBoots(), 24).$this->intToSaltBytes($this->localBoot, 24);
        }

        return ['key' => $key, 'salt' => $salt, 'iv' => $this->generateIV($preIV, $salt)];
    }
}
