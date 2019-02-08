<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Exception\RuntimeException;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;
use FreeDSx\Snmp\Protocol\Factory\SecurityParametersFactory;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Socket\PduInterface;

/**
 * Represents the SNMPv3 Message format. RFC 3412.
 *
 * SNMPv3Message ::= SEQUENCE {
 *     -- identify the layout of the SNMPv3Message
 *     -- this element is in same position as in SNMPv1
 *     -- and SNMPv2c, allowing recognition
 *     -- the value 3 is used for snmpv3
 *     msgVersion INTEGER ( 0 .. 2147483647 ),
 *     -- administrative parameters
 *     msgGlobalData HeaderData,
 *     -- security model-specific parameters
 *     -- format defined by Security Model
 *     msgSecurityParameters OCTET STRING,
 *     msgData  ScopedPduData
 * }
 *
 * ScopedPduData ::= CHOICE {
 *     plaintext    ScopedPDU,
 *     encryptedPDU OCTET STRING  -- encrypted scopedPDU value
 * }
 *
 * ScopedPDU ::= SEQUENCE {
 *     contextEngineID  OCTET STRING,
 *     contextName      OCTET STRING,
 *     data             ANY -- e.g., PDUs as defined in [RFC3416]
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class AbstractMessageV3 implements PduInterface
{
    protected const VERSION = 3;

    /**
     * @var MessageHeader
     */
    protected $header;

    /**
     * @var null|ScopedPdu
     */
    protected $scopedPdu;

    /**
     * @var null|string
     */
    protected $encryptedPdu;

    /**
     * @var SecurityParametersInterface|null
     */
    protected $securityParams;

    /**
     * @param MessageHeader $header
     * @param null|ScopedPdu $scopedPdu
     * @param null $encryptedPdu
     * @param SecurityParametersInterface|null $securityParams
     */
    public function __construct(MessageHeader $header, ?ScopedPdu $scopedPdu, $encryptedPdu = null, ?SecurityParametersInterface $securityParams = null)
    {
        $this->header = $header;
        $this->encryptedPdu = $encryptedPdu;
        $this->scopedPdu = $scopedPdu;
        $this->securityParams = $securityParams;
    }

    /**
     * @return MessageHeader
     */
    public function getMessageHeader() : MessageHeader
    {
        return $this->header;
    }

    /**
     * @return SecurityParametersInterface|null
     */
    public function getSecurityParameters() : ?SecurityParametersInterface
    {
        return $this->securityParams;
    }

    /**
     * @return null|string
     */
    public function getEncryptedPdu()
    {
        return $this->encryptedPdu;
    }

    /**
     * @return int
     */
    public function getVersion() : int
    {
        return self::VERSION;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $securityParams = '';
        if ($this->securityParams) {
            $securityParams = (new SnmpEncoder())->encode($this->securityParams->toAsn1());
        }

        if ($this->encryptedPdu !== null) {
            $scopedPdu = Asn1::octetString($this->encryptedPdu);
        } elseif ($this->scopedPdu !== null) {
            $scopedPdu = $this->scopedPdu->toAsn1();
        } else {
            throw new RuntimeException('Either the scoped PDU or the encrypted scoped PDU must be set');
        }

        return Asn1::sequence(
            Asn1::integer(self::VERSION),
            $this->header->toAsn1(),
            Asn1::octetString($securityParams),
            $scopedPdu
        );
    }

    /**
     * Extracts the common parts of the SNMP v3 message, then the request / response can be determined depending on
     * whether we are handling a request or response.
     *
     * @param AbstractType $type
     * @return array
     * @throws ProtocolException
     */
    protected static function parseCommonElements(AbstractType $type)
    {
        if (!($type instanceof SequenceType && count($type->getChildren()) === 4)) {
            throw new ProtocolException('The SNMP message must be a sequence with at least 4 elements.');
        }
        $version = $type->getChild(0);
        if (!($version instanceof IntegerType && $version->getValue() === static::VERSION)) {
            throw new ProtocolException(sprintf(
                'Expected SNMP version %s, got %s.',
                static::VERSION,
                $version->getValue()
            ));
        }
        $header = MessageHeader::fromAsn1($type->getChild(1));

        $securityParams = $type->getChild(2);
        if (!$securityParams instanceof OctetStringType) {
            throw new ProtocolException(sprintf(
                'The security parameters must be an octet string, got %s',
                get_class($securityParams)
            ));
        }
        $securityParamsValue = '';
        if ($securityParams->getValue() !== '') {
            $securityParamsValue = SecurityParametersFactory::get($header->getSecurityModel(), $securityParams);
        }

        return [
            $header,
            $securityParamsValue,
            $type->getChild(3)
        ];
    }
}
