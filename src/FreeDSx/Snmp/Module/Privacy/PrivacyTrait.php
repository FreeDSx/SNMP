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
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\ScopedPdu;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModuleInterface;
use FreeDSx\Snmp\Protocol\SnmpEncoder;

/**
 * Implements a common structure for privacy module implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PrivacyTrait
{
    /**
     * @var int
     */
    protected static $maxSalt = 2147483647;

    /**
     * @var int
     */
    protected $localBoot;

    /**
     * @var string
     */
    protected $algorithm;

    /**
     * {@inheritdoc}
     */
    public function decryptData(AbstractMessageV3 $message, AuthenticationModuleInterface $authMod, string $privPwd) : AbstractMessageV3
    {
        /** @var UsmSecurityParameters $usm */
        $usm = $message->getSecurityParameters();

        # 1) If the privParameters field is not an 8-octet OCTET STRING, then
        #    an error indication (decryptionError) is returned to the calling
        #    module.
        if (\strlen($usm->getPrivacyParams()) !== 8) {
            throw new SnmpEncryptionException(sprintf(
                'The privParameters must be 8 octets long, but it is %s.',
                \strlen($usm->getPrivacyParams())
            ));
        }

        # 2) The "salt" is extracted from the privParameters field.
        $salt = $usm->getPrivacyParams();

        # 3) The secret cryptKey and the "salt" are then used to construct the
        #    DES decryption key and pre-IV (from which the IV is computed as
        #    described in section 8.1.1.1).
        $cryptKey = $authMod->generateKey(
            $privPwd,
            $usm->getEngineId()
        );
        list('key' => $key, 'iv' => $iv) = $this->toKeySaltIV($cryptKey, $usm, $authMod, $salt);

        # 4) The encryptedPDU is then decrypted (as described in section 8.1.1.3).
        $encryptedPdu = $this->validateEncryptedPdu($message->getEncryptedPdu());
        $decryptedPdu = \openssl_decrypt($encryptedPdu, $this->algoAlias(), $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);

        # 5) If the encryptedPDU cannot be decrypted, then an error indication
        #    (decryptionError) is returned to the calling module.
        if ($decryptedPdu === false) {
            throw new SnmpEncryptionException('Unable to decrypt the scopedPdu');
        }

        $pduFactory = $message instanceof MessageRequestInterface ? ScopedPduRequest::class : ScopedPduResponse::class;
        try {
            $pdu = \call_user_func($pduFactory.'::fromAsn1', (new SnmpEncoder())->decode($decryptedPdu));
        } catch (\Exception|\Throwable $e) {
            throw new SnmpEncryptionException('Failed to assemble decrypted PDU.', $e->getCode(), $e);
        }
        $this->setPduDataInMessage($message, null, $pdu);

        return $message;
    }

    /**
     * {@inheritdoc}
     */
    public function encryptData(AbstractMessageV3 $message, AuthenticationModuleInterface $authMod, string $password) : AbstractMessageV3
    {
        /** @var  UsmSecurityParameters $usm */
        $usm = $message->getSecurityParameters();

        # RFC 3414, Section 11.2. Passwords must be at least 8 characters in length
        if (\strlen($password) < 8) {
            throw new SnmpEncryptionException('The privacy password must be at least 8 characters long.');
        }

        # 1) The secret cryptKey is used to construct the DES encryption key,
        #    the "salt" and the DES pre-IV (from which the IV is computed as
        #    described in section 8.1.1.1).
        $cryptKey = $authMod->generateKey(
            $password,
            $usm->getEngineId()
        );
        list('key' => $key, 'salt' => $salt, 'iv' => $iv) = $this->toKeySaltIV($cryptKey, $usm, $authMod);

        # 2) The privParameters field is set to the serialization according to
        #    the rules in [RFC3417] of an OCTET STRING representing the "salt"
        #    string.
        $usm->setPrivacyParams($salt);

        # RFC 3414, Section 8.1.1.1:
        #    The "salt" integer is then modified.  We recommend that it be incremented by one and
        #    wrap when it reaches the maximum value.
        $this->localBoot = ($this->localBoot === self::$maxSalt) ? 0 : ($this->localBoot + 1);

        # 3) The scopedPDU is encrypted (as described in section 8.1.1.2)
        #    and the encrypted data is serialized according to the rules in
        #    [RFC3417] as an OCTET STRING.
        $scopedPdu = $this->validateEncodedPdu((new SnmpEncoder())->encode($message->getScopedPdu()->toAsn1()));

        $encryptedPdu = \openssl_encrypt($scopedPdu, $this->algoAlias(), $key, OPENSSL_RAW_DATA, $iv);
        if ($encryptedPdu === false) {
            throw new SnmpEncryptionException(sprintf(
                'Unable to encrypt the scopedPdu using %s',
                $this->algorithm
            ));
        }
        $this->setPduDataInMessage($message, $encryptedPdu, null, true);

        return $message;
    }

    /**
     * This should return an associative array containing:
     *
     * ['key' => $key, 'salt' => $salt, 'iv' => $iv]
     *
     * @param string $cryptKey
     * @param UsmSecurityParameters $usm
     * @param AuthenticationModuleInterface $authMod
     * @param null|string $salt
     * @return array
     */
    abstract protected function toKeySaltIV($cryptKey, UsmSecurityParameters $usm, AuthenticationModuleInterface $authMod, $salt = null) : array;

    /**
     * @param $scopedPdu
     * @return string
     */
    abstract protected function validateEncodedPdu($scopedPdu);

    /**
     * @param $encryptedPdu
     * @return string
     * @throws SnmpEncryptionException
     */
    abstract protected function validateEncryptedPdu($encryptedPdu);

    /**
     * @param int $int
     * @param int $startAt
     * @return string
     */
    protected function intToSaltBytes(int $int, int $startAt)
    {
        $salt = '';

        for ($i = $startAt; $i >= 0; $i -= 8) {
            $salt  .= \chr(($int >> $i) & 0xff);
        }

        return $salt;
    }

    /**
     * Uses the key localization method from the 3DES Reeder draft to deal with keys that are not long enough.
     *
     * @param AuthenticationModuleInterface $authMod
     * @param string $cryptKey
     * @param EngineId $engineId
     * @param int $keySize
     * @return string
     */
    protected function localizeReeder(AuthenticationModuleInterface $authMod, $cryptKey, EngineId $engineId, int $keySize)
    {
        # Section 2.1
        # -----------
        # Chaining is described as follows.  First, run the password-to-key
        # algorithm with inputs of the passphrase and engineID as described in
        # the USM document.  This will output as many key bits as the hash
        # algorithm used to implement the password-to-key algorithm.  Secondly,
        # run the password-to-key algorithm again with the previous output
        # (instead of the passphrase) and the same engineID as inputs.  Repeat
        # this process as many times as necessary in order to generate the
        # minimum number of key bits for the chosen privacy protocol.  The
        # outputs of each execution are concatenated into a single string of
        # key bits.
        # -----------
        # The first step is already done.
        while (\strlen($cryptKey) < $keySize) {
            $cryptKey .= $authMod->generateKey($cryptKey, $engineId);
        }

        # When this process results in more key bits than are necessary, only
        # the most significant bits of the string should be used.
        #
        # For example, if password-to-key implemented with SHA creates a
        # 40-octet string string for use as key bits, only the first 32 octets
        # will be used for usm3DESEDEPrivProtocol.
        return substr($cryptKey, 0, $keySize);
    }

    /**
     * Uses the key localization method from the AES Blumenthal draft to deal with keys that are not long enough.
     *
     * @param AuthenticationModuleInterface $authMod
     * @param $cryptKey
     * @param int $keySize
     * @return string
     */
    protected function localizeBlumenthal(AuthenticationModuleInterface $authMod, $cryptKey, int $keySize)
    {
        $c = \ceil($keySize / strlen($cryptKey));

        for ($i = 0; $i < $c; $i++) {
            $cryptKey .= $authMod->hash($cryptKey);
        }

        return \substr($cryptKey, 0, $keySize);
    }

    /**
     * @return string
     */
    protected function algoAlias() : string
    {
        if (\defined('self::ALIASES') && \array_key_exists($this->algorithm, self::ALIASES)) {
            return self::ALIASES[$this->algorithm];
        }

        return $this->algorithm;
    }

    /**
     * @param AbstractMessageV3 $message
     * @param string|null $encryptedData
     * @param ScopedPdu|null $pdu
     * @param bool $encOnly
     */
    protected function setPduDataInMessage(AbstractMessageV3 $message, $encryptedData, ?ScopedPdu $pdu, bool $encOnly = false) : void
    {
        $requestObject = new \ReflectionObject($message);

        if (!$encOnly) {
            $pduProperty = $requestObject->getProperty('scopedPdu');
            $pduProperty->setAccessible(true);
            $pduProperty->setValue($message, $pdu);
        }

        $encryptedProperty = $requestObject->getProperty('encryptedPdu');
        $encryptedProperty->setAccessible(true);
        $encryptedProperty->setValue($message, $encryptedData);
    }
}
