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
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModuleInterface;

/**
 * RFC 3826 / draft-blumenthal-aes-usm-04
 *
 * AES privacy mechanisms for encrypting / decrypting the ScopedPDU.
 *
 * @see https://tools.ietf.org/html/draft-blumenthal-aes-usm-04
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AESPrivacyModule implements PrivacyModuleInterface
{
    use PrivacyTrait {
        encryptData as encrypt;
        decryptData as decrypt;
    }

    protected const ALIASES = [
        'aes' => 'aes-128-cfb',
        'aes128' => 'aes-128-cfb',
        'aes192' => 'aes-192-cfb',
        'aes256' => 'aes-256-cfb',
        'aes192blu' => 'aes-192-cfb',
        'aes256blu' => 'aes-256-cfb',
    ];

    public const ALGORITHMS = [
        'aes',
        'aes128',
        'aes192',
        'aes256',
        'aes192blu',
        'aes256blu',
        'aes-128-cfb',
        'aes-192-cfb',
        'aes-256-cfb',
    ];

    protected const KEY_SIZE = [
        'aes-128-cfb' => 16,
        'aes-192-cfb' => 24,
        'aes-256-cfb' => 32,
    ];

    /**
     * @var bool
     */
    protected $has64BitSupport;

    /**
     * @param string $algorithm
     * @param int|null $localBoot
     * @throws \Exception
     */
    public function __construct(string $algorithm, ?int $localBoot = null)
    {
        $this->algorithm = $algorithm;
        $this->has64BitSupport = \is_int(9223372036854775807);
        if ($localBoot === null) {
            if ($this->has64BitSupport) {
                self::$maxSalt = 9223372036854775807;
                $this->localBoot = \random_int(0, self::$maxSalt);
            }
        } else {
            $this->localBoot = $localBoot;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decryptData(AbstractMessageV3 $message, AuthenticationModuleInterface $authMod, string $privPwd) : AbstractMessageV3
    {
        if (!$this->has64BitSupport) {
            throw new SnmpEncryptionException('AES privacy requires 64bit int support.');
        }

        return $this->decrypt($message, $authMod, $privPwd);
    }

    /**
     * {@inheritdoc}
     */
    public function encryptData(AbstractMessageV3 $message, AuthenticationModuleInterface $authMod, string $privPwd) : AbstractMessageV3
    {
        if (!$this->has64BitSupport) {
            throw new SnmpEncryptionException('AES privacy requires 64bit int support.');
        }

        return $this->encrypt($message, $authMod, $privPwd);
    }

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
        $keySize = self::KEY_SIZE[$this->algoAlias()];
        $keyTooShort = (\strlen($cryptKey) < $keySize);

        if ($keyTooShort && \substr($this->algorithm, -3) === 'blu') {
            $cryptKey = $this->localizeBlumenthal($authMod, $cryptKey, $keySize);
        } elseif ($keyTooShort) {
            $cryptKey = $this->localizeReeder($authMod, $cryptKey, $usm->getEngineId(), $keySize);
        }

        # RFC 3826, Section 3.1.2.1 / RFC draft-blumenthal-aes-usm-04, Section 3.1.2.1
        $key = \substr($cryptKey, 0, $keySize);

        # The 64bit int local boot is the salt
        if ($salt === null) {
            $salt = $this->intToSaltBytes($this->localBoot, 56);
        }

        # The IV is concatenated as follows: the 32-bit snmpEngineBoots is
        # converted to the first 4 octets (Most Significant Byte first), the
        # 32-bit snmpEngineTime is converted to the subsequent 4 octets (Most
        # Significant Byte first), and the 64-bit integer is then converted to
        # the last 8 octets (Most Significant Byte  first).
        $iv = $this->intToSaltBytes($usm->getEngineBoots(), 24);
        $iv .= $this->intToSaltBytes($usm->getEngineTime(), 24);
        $iv .= $salt;

        return ['key' => $key, 'salt' => $salt, 'iv' => $iv];
    }

    /**
     * {@inheritdoc}
     */
    protected function validateEncodedPdu($scopedPdu)
    {
        return $scopedPdu;
    }

    /**
     * {@inheritdoc}
     */
    protected function validateEncryptedPdu($encryptedPdu)
    {
        return $encryptedPdu;
    }
}
