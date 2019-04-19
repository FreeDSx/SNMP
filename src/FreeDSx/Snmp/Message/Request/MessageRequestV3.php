<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message\Request;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;
use FreeDSx\Snmp\Request\RequestInterface;

/**
 * Represents a SNMPv3 Message Request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageRequestV3 extends AbstractMessageV3 implements MessageRequestInterface
{
    /**
     * @param MessageHeader $header
     * @param ScopedPduRequest $scopedPduRequest
     * @param null|string $encryptedPdu
     * @param SecurityParametersInterface|null $securityParams
     */
    public function __construct(MessageHeader $header, ?ScopedPduRequest $scopedPduRequest, $encryptedPdu = null, ?SecurityParametersInterface $securityParams = null)
    {
        parent::__construct($header, $scopedPduRequest, $encryptedPdu, $securityParams);
    }

    /**
     * @return static
     */
    public function setSecurityParameters(?SecurityParametersInterface $securityParams) : self
    {
        $this->securityParams = $securityParams;

        return $this;
    }

    /**
     * @param MessageHeader $header
     */
    public function setMessageHeader(MessageHeader $header): void
    {
        $this->header = $header;
    }

    /**
     * @return RequestInterface
     */
    public function getRequest(): RequestInterface
    {
        return $this->scopedPdu->getRequest();
    }

    /**
     * @param RequestInterface $request
     * @return $this|MessageRequestInterface
     */
    public function setRequest(RequestInterface $request)
    {
        $this->scopedPdu->setRequest($request);

        return $this;
    }

    /**
     * @return static
     */
    public function setEncryptedPdu(?string $encryptedPdu) : self
    {
        $this->encryptedPdu = $encryptedPdu;

        return $this;
    }

    public function getScopedPdu() : ?ScopedPduRequest
    {
        return $this->scopedPdu;
    }

    /**
     * @return static
     */
    public function setScopedPdu(?ScopedPduRequest $request) : self
    {
        $this->scopedPdu = $request;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $asn1)
    {
        [$header, $securityParams, $pdu] = self::parseCommonElements($asn1);

        $encryptedPdu = null;
        $scopedPdu = null;
        if ($pdu instanceof OctetStringType) {
            $encryptedPdu = $pdu->getValue();
        } elseif ($pdu instanceof SequenceType) {
            $scopedPdu = ScopedPduRequest::fromAsn1($pdu);
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
