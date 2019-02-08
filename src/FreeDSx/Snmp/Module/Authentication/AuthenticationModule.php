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
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Protocol\SnmpEncoder;

/**
 * Implements SHA / MD5 based authentication mechanisms.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AuthenticationModule implements AuthenticationModuleInterface
{
    public const ALGORITHMS = [
        'md5',
        'sha1',
        'sha224',
        'sha256',
        'sha384',
        'sha512',
    ];

    /**
     * RFC 7860, Section  4.1 / 4.2
     */
    protected const M = [
        'md5' => 16,
        'sha1' => 20,
        'sha224' => 28,
        'sha256' => 32,
        'sha384' => 48,
        'sha512' => 64,
    ];

    /**
     * RFC 7860, Section 4.1 / 4.2
     */
    protected const N = [
        'md5' => 12,
        'sha1' => 12,
        'sha224' => 16,
        'sha256' => 24,
        'sha384' => 32,
        'sha512' => 48,
    ];

    /**
     * @var string
     */
    protected $algorithm;

    /**
     * @param string $algorithm
     */
    public function __construct(string $algorithm)
    {
        $this->algorithm = $algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticateIncomingMsg(AbstractMessageV3 $message, string $password) : AbstractMessageV3
    {
        /** @var UsmSecurityParameters $usm */
        $usm = $message->getSecurityParameters();
        $digest = $usm->getAuthParams();
        if (\strlen($digest) !== self::N[$this->algorithm]) {
            throw new SnmpAuthenticationException(sprintf(
                'Expected a digest of %s bytes, but it is %s.',
                self::N[$this->algorithm],
                strlen($digest)
            ));
        }

        # As in an outgoing message, replace the digest with zero octets.
        $usm->setAuthParams(\str_repeat("\x00", self::N[$this->algorithm]));
        $hmac = $this->generateHMAC($message, $password, $usm->getEngineId());
        if ($hmac !== $digest) {
            throw new SnmpAuthenticationException('The received message contains the wrong digest.');
        }

        return $message;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticateOutgoingMsg(AbstractMessageV3 $message, string $password) : AbstractMessageV3
    {
        # RFC 3414, Section 11.2. Passwords must be at least 8 characters in length
        if (\strlen($password) < 8) {
            throw new SnmpAuthenticationException('The authentication password must be at least 8 characters long.');
        }
        /** @var UsmSecurityParameters $usm */
        $usm = $message->getSecurityParameters();

        # RFC 7860, Section 4.2.1. Step 1:
        #     The msgAuthenticationParameters field is set to the serialization
        #     of an OCTET STRING containing N zero octets; it is serialized
        #     according to the rules in [RFC3417].
        $usm->setAuthParams(\str_repeat("\x00", self::N[$this->algorithm]));
        # RFC 7860, Section 4.2.1. Step 4:
        #     The msgAuthenticationParameters field is replaced with the MAC
        #     obtained in the previous step.
        $usm->setAuthParams($this->generateHMAC($message, $password, $usm->getEngineId()));

        return $message;
    }

    /**
     * RFC 7860, Section 9.3:
     *
     * Derivation of Keys from Passwords
     *
     * If secret keys to be used for HMAC-SHA-2 authentication protocols are
     * derived from passwords, the derivation SHOULD be performed using the
     * password-to-key algorithm from Appendix A.1 of RFC 3414 with MD5
     * being replaced by the SHA-2 hash function H used in the HMAC-SHA-2
     * authentication protocol.
     *
     * @param string $password
     * @param $engineId
     * @return string
     */
    public function generateKey(string $password, EngineId $engineId)
    {
        # RFC 7860, Section 9.3, first bullet point:
        #     forming a string of length 1,048,576 octets by repeating the value
        #     of the password as often as necessary, truncating accordingly, and
        #     using the resulting string as the input to the hash function H.
        #     The resulting digest, termed "digest1", is used in the next step.
        $digest1 = $this->hash(\substr(
            str_repeat($password, (\ceil(10478576 / \strlen($password)))),
            0,
            1048576
        ));

        # RFC 7860, Section 9.3, second bullet point:
        #     forming a second string by concatenating digest1, the SNMP
        #     engine's snmpEngineID value, and digest1.  This string is used as
        #     input to the hash function H.
        $key = $this->hash($digest1.$engineId->toBinary().$digest1);

        return $key;
    }

    /**
     * {@inheritdoc}
     */
    public function hash($value)
    {
        $digest = \hash($this->algorithm, $value, true);
        $this->throwOnHashError($digest);

        return $digest;
    }

    /**
     * {@inheritdoc}
     */
    public static function supports() : array
    {
        return self::ALGORITHMS;
    }

    /**
     * @param $result
     * @throws SnmpAuthenticationException
     */
    protected function throwOnHashError($result) : void
    {
        if ($result === false) {
            throw new SnmpAuthenticationException(sprintf(
                'Unable to hash value using using algorithm %s.',
                $this->algorithm
            ));
        }
    }

    /**
     * @param AbstractMessageV3 $message
     * @param string $password
     * @param EngineId $engineId
     * @return string
     * @throws SnmpAuthenticationException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     */
    protected function generateHMAC(AbstractMessageV3 $message, string $password, EngineId $engineId)
    {
        # RFC 7860, Section 4.2.1. Step 2:
        #     Using the secret authKey of M octets, the HMAC is calculated over
        #     the wholeMsg according to RFC 6234 with hash function H.
        $key = $this->generateKey($password, $engineId);
        $hmac = \hash_hmac(
            $this->algorithm,
            (new SnmpEncoder())->encode($message->toAsn1()),
            \substr($key, 0, self::M[$this->algorithm]),
            true
        );
        $this->throwOnHashError($hmac);

        # RFC 7860, Section 4.2.1. Step 3:
        #     The N first octets of the above HMAC are taken as the computed
        #     MAC value.
        return \substr($hmac, 0, self::N[$this->algorithm]);
    }
}
