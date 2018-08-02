<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message\Response;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;
use FreeDSx\Snmp\Response\ResponseInterface;

/**
 * Represents a SNMPv3 Message Response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageResponseV3 extends AbstractMessageV3 implements MessageResponseInterface
{
    /**
     * @param MessageHeader $header
     * @param ScopedPduResponse $scopedPdu
     * @param null|string $encryptedPdu
     * @param SecurityParametersInterface|null $securityParams
     */
    public function __construct(MessageHeader $header, ?ScopedPduResponse $scopedPdu, $encryptedPdu = null, ?SecurityParametersInterface $securityParams = null)
    {
        parent::__construct($header, $scopedPdu, $encryptedPdu, $securityParams);
    }

    /**
     * @return ResponseInterface
     */
    public function getResponse() : ResponseInterface
    {
        return $this->scopedPdu->getResponse();
    }

    /**
     * @return ScopedPduResponse
     */
    public function getScopedPdu() : ?ScopedPduResponse
    {
        return $this->scopedPdu;
    }

    /**
     * @return null|string
     */
    public function getEncryptedPdu()
    {
        return $this->encryptedPdu;
    }

    public static function fromAsn1(AbstractType $asn1)
    {
        list($header, $securityParams, $pdu) = self::parseCommonElements($asn1);

        $encryptedPdu = null;
        $scopedPdu = null;
        if ($pdu instanceof OctetStringType) {
            $encryptedPdu = $pdu->getValue();
        } elseif ($pdu instanceof SequenceType) {
            $scopedPdu = ScopedPduResponse::fromAsn1($pdu);
        } else {
            throw new ProtocolException(sprintf(
               'Expected either an octet string or sequence for scoped pdu data, got %s.',
               get_class($pdu)
            ));
        }

        return new self(
            $header,
            $scopedPdu,
            $encryptedPdu,
            $securityParams
        );
    }
}
