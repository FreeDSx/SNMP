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
 * Implements 3DES privacy based on the draft RFC (that was never finalized).
 *
 * @see https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DES3PrivacyModule implements PrivacyModuleInterface
{
    use PrivacyTrait,
        DESPrivacyTrait;

    protected const ALIASES = [
        '3des' => 'des-ede3-cbc',
    ];

    protected const ALGORITHMS = [
        '3des',
        'des-ede3-cbc',
    ];

    /**
     * {@inheritdoc}
     */
    public static function supports(): array
    {
        return self::ALGORITHMS;
    }

    /**
     * {@inheritdoc}
     */
    protected function toKeySaltIV($cryptKey, UsmSecurityParameters $usm, AuthenticationModuleInterface $authMod, $salt = null): array
    {
        $cryptKey = $this->localizeReeder($authMod, $cryptKey, $usm->getEngineId(), 32);

        # Section 5.1.1.1.1
        # The first 24 octets of the 32-octet secret (private privacy key) are
        # used as a 3DES-EDE key.  Since 3DES-EDE uses only 168 bits, the Least
        # Significant Bit in each octet is disregarded.
        $key = \substr($cryptKey, 0, 24);

        # Section 5.1.1.1.2
        # The last 8 octets of the 32-octet secret (private privacy key) are
        # used as pre-IV.
        $preIV = \substr($cryptKey, 24, 8);

        if ($salt === null) {
            # In order to ensure that the IV for two different packets encrypted by
            # the same key, are not the same (i.e., the IV does not repeat over the
            # lifetime of the private key) we need to "salt" the pre-IV with
            # something unique per packet.  An 8-octet string is used as the
            # "salt".  The concatenation of the generating SNMP engine's 32-bit
            # snmpEngineBoots and a local 32-bit integer, that the encryption
            # engine maintains, is input to the "salt".  The 32-bit integer is
            # initialized to an arbitrary value at boot time.
            $salt = $this->intToSaltBytes($usm->getEngineBoots(), 24).$this->intToSaltBytes($this->localBoot, 24);
            # To achieve effective bit spreading, the complete 8-octet "salt" value
            # SHOULD be hashed using the usmUserAuthProtocol.  This may be
            # performed using the authentication algorithm directly, or by passing
            # the "salt" as input the the password-to-key algorithm.  The result of
            # the hash is truncated to 8 octets.
            $salt = \substr($authMod->generateKey($salt, $usm->getEngineId()), 0, 8);
        }

        return ['key' => $key, 'salt' => $salt, 'iv' => $this->generateIV($preIV, $salt)];
    }
}
