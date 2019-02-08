<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message\Security;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Protocol\SnmpEncoder;

/**
 * Represents the USM Security Parameters. RFC 3414, Section 2.4.
 *
 * UsmSecurityParameters ::=
 *     SEQUENCE {
 *         -- global User-based security parameters
 *            msgAuthoritativeEngineID     OCTET STRING,
 *            msgAuthoritativeEngineBoots  INTEGER (0..2147483647),
 *            msgAuthoritativeEngineTime   INTEGER (0..2147483647),
 *            msgUserName                  OCTET STRING (SIZE(0..32)),
 *         -- authentication protocol specific parameters
 *            msgAuthenticationParameters  OCTET STRING,
 *         -- privacy protocol specific parameters
 *            msgPrivacyParameters         OCTET STRING
 *     }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class UsmSecurityParameters implements SecurityParametersInterface
{
    /**
     * @var null|EngineId
     */
    protected $engineId;

    /**
     * @var int
     */
    protected $engineBoots;

    /**
     * @var int
     */
    protected $engineTime;

    /**
     * @var string
     */
    protected $username;

    /**
     * @var null|string
     */
    protected $authParams;

    /**
     * @var null|string
     */
    protected $privacyParams;

    /**
     * @param null|EngineId $engineId
     * @param int $engineBoots
     * @param int $engineTime
     * @param string $username
     * @param string $authParams
     * @param string $privacyParams
     */
    public function __construct(?EngineId $engineId = null, int $engineBoots = 0, int $engineTime = 0, string $username = '', ?string $authParams = null, ?string $privacyParams = null)
    {
        $this->engineId = $engineId;
        $this->engineBoots = $engineBoots;
        $this->engineTime = $engineTime;
        $this->username = $username;
        $this->authParams = $authParams;
        $this->privacyParams = $privacyParams;
    }

    /**
     * @return string
     */
    public function getAuthParams() : ?string
    {
        return $this->authParams;
    }

    /**
     * @param null|string $authParams
     * @return UsmSecurityParameters
     */
    public function setAuthParams(?string $authParams)
    {
        $this->authParams = $authParams;

        return $this;
    }

    /**
     * @return int
     */
    public function getEngineBoots() : int
    {
        return $this->engineBoots;
    }

    /**
     * @param int $engineBoots
     * @return UsmSecurityParameters
     */
    public function setEngineBoots(int $engineBoots)
    {
        $this->engineBoots = $engineBoots;

        return $this;
    }

    /**
     * @return null|EngineId
     */
    public function getEngineId() : ?EngineId
    {
        return $this->engineId;
    }

    /**
     * @param null|EngineId $engineId
     * @return UsmSecurityParameters
     */
    public function setEngineId(?EngineId $engineId)
    {
        $this->engineId = $engineId;

        return $this;
    }

    /**
     * @return int
     */
    public function getEngineTime() : int
    {
        return $this->engineTime;
    }

    /**
     * @param int $engineTime
     * @return UsmSecurityParameters
     */
    public function setEngineTime(int $engineTime)
    {
        $this->engineTime = $engineTime;

        return $this;
    }

    /**
     * @return string
     */
    public function getPrivacyParams() : ?string
    {
        return $this->privacyParams;
    }

    /**
     * @param null|string $privacyParams
     * @return UsmSecurityParameters
     */
    public function setPrivacyParams(?string $privacyParams)
    {
        $this->privacyParams = $privacyParams;

        return $this;
    }

    /**
     * @return string
     */
    public function getUsername() : string
    {
        return $this->username;
    }

    /**
     * @param string $username
     * @return UsmSecurityParameters
     */
    public function setUsername(string $username)
    {
        $this->username = $username;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getSecurityModel(): int
    {
        return 3;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $engineId = ($this->engineId === null) ? '' : $this->engineId->toBinary();

        return Asn1::sequence(
            Asn1::octetString($engineId),
            Asn1::integer($this->engineBoots),
            Asn1::integer($this->engineTime),
            Asn1::octetString($this->username),
            Asn1::octetString((string) $this->authParams),
            Asn1::octetString((string) $this->privacyParams)
        );
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $usm = (new SnmpEncoder())->decode($type->getValue());
        if (!($usm instanceof SequenceType && \count($usm->getChildren()) === 6)) {
            throw new ProtocolException('Expected the USM to be a sequence type with 6 elements.');
        }

        $args = [
            $usm->getChild(0),
            $usm->getChild(1),
            $usm->getChild(2),
            $usm->getChild(3),
            $usm->getChild(4),
            $usm->getChild(5)
        ];

        foreach ($args as $i => $type) {
            if (($i === 1 || $i === 2) && !$type instanceof IntegerType) {
                throw new ProtocolException(sprintf(
                    'The USM is malformed. Expected an integer type, got %s.',
                    get_class($type)
                ));
            }
            if (!($i === 1 || $i === 2) && !$type instanceof OctetStringType) {
                throw new ProtocolException(sprintf(
                    'The USM is malformed. Expected an octet string type, got %s.',
                    get_class($type)
                ));
            }
        }
        $args = \array_map(function ($type) {
            /** @var AbstractType $type */
            return $type->getValue();
        }, $args);
        $args[0] = ($args[0] === '') ? null : EngineId::fromBinary($args[0]);


        return new self(...$args);
    }
}
