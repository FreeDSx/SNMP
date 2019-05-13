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

/**
 * Common methods shared by DES / 3DES privacy  mechanisms.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait DESPrivacyTrait
{
    /**
     * @param string $algorithm
     * @param int|null $localBoot
     * @throws \Exception
     */
    public function __construct(string $algorithm, ?int $localBoot = null)
    {
        $this->algorithm = $algorithm;
        $this->localBoot = ($localBoot === null) ? \random_int(0, self::$maxSalt) : $localBoot;
    }

    protected function generateIV(string $preIV, string $salt) : string
    {
        $iv = '';

        # The resulting "salt" is then XOR-ed with the pre-IV to obtain the IV.
        for ($i = 0; $i < 8; $i++) {
            $iv .= \chr(\ord($salt[$i]) ^ \ord($preIV[$i]));
        }

        return $iv;
    }

    /**
     * {@inheritdoc}
     */
    protected function validateEncodedPdu(string $scopedPdu) : string
    {
        $pduLength = \strlen($scopedPdu);

        $mod = $pduLength % 8;
        if ($mod !== 0) {
            $scopedPdu .= \str_repeat("\x00", 8 - $mod);
        }

        return $scopedPdu;
    }

    /**
     * {@inheritdoc}
     */
    protected function validateEncryptedPdu(string $encryptedPdu) : string
    {
        if (\strlen($encryptedPdu) % 8 !== 0) {
            throw new SnmpEncryptionException('The encrypted PDU must be a multiple of 8 octets, but it is not');
        }

        return $encryptedPdu;
    }
}
