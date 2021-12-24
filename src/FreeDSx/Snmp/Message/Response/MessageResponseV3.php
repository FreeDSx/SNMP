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
use FreeDSx\Snmp\Exception\RuntimeException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;

/**
 * Represents a SNMPv3 Message Response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageResponseV3 extends AbstractMessageV3 implements MessageResponseInterface
{
    /**
     * @var ScopedPduResponse|null
     */
    protected $scopedPdu;

    /**
     * @param MessageHeader $header
     * @param ScopedPduResponse|null $scopedPdu
     * @param null|string $encryptedPdu
     * @param SecurityParametersInterface|null $securityParams
     */
    public function __construct(
        MessageHeader $header,
        ?ScopedPduResponse $scopedPdu,
        $encryptedPdu = null,
        ?SecurityParametersInterface $securityParams = null
    ) {
        parent::__construct(
            $header,
            $scopedPdu,
            $encryptedPdu,
            $securityParams
        );
    }

    /**
     * @return Pdu
     */
    public function getResponse(): Pdu
    {
        if ($this->scopedPdu === null) {
            throw new RuntimeException('The scopedPdu is not set.');
        }

        return $this->scopedPdu->getResponse();
    }

    /**
     * @return ScopedPduResponse|null
     */
    public function getScopedPdu() : ?ScopedPduResponse
    {
        return $this->scopedPdu;
    }

    /**
     * @return null|string
     */
    public function getEncryptedPdu(): ?string
    {
        return $this->encryptedPdu;
    }

    /**
     * @inheritDoc
     * @throws ProtocolException
     */
    public static function fromAsn1(AbstractType $asn1): MessageResponseV3
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
