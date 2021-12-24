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
use FreeDSx\Snmp\Exception\RuntimeException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;

/**
 * Represents a SNMPv3 Message Request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageRequestV3 extends AbstractMessageV3 implements MessageRequestInterface
{
    /**
     * @var null|ScopedPduRequest
     */
    protected $scopedPdu;

    /**
     * @param MessageHeader $header
     * @param ScopedPduRequest|null $scopedPdu
     * @param null|string $encryptedPdu
     * @param SecurityParametersInterface|null $securityParams
     */
    public function __construct(
        MessageHeader $header,
        ?ScopedPduRequest $scopedPdu,
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
     * @param SecurityParametersInterface|null $securityParams
     * @return MessageRequestV3
     */
    public function setSecurityParameters(?SecurityParametersInterface $securityParams): self
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
     * @inheritDoc
     */
    public function getRequest(): Pdu
    {
        if ($this->scopedPdu === null) {
            throw new RuntimeException('The scopedPdu is not set.');
        }

        return $this->scopedPdu->getRequest();
    }

    /**
     * @param Pdu $request
     * @return $this
     */
    public function setRequest(Pdu $request): self
    {
        if ($this->scopedPdu === null) {
            throw new RuntimeException('The scopedPdu is not set.');
        }
        $this->scopedPdu->setRequest($request);

        return $this;
    }

    /**
     * @return $this
     */
    public function setEncryptedPdu(?string $encryptedPdu): self
    {
        $this->encryptedPdu = $encryptedPdu;

        return $this;
    }

    /**
     * @return ScopedPduRequest|null
     */
    public function getScopedPdu() : ?ScopedPduRequest
    {
        return $this->scopedPdu;
    }

    /**
     * @param ScopedPduRequest|null $request
     * @return $this
     */
    public function setScopedPdu(?ScopedPduRequest $request): self
    {
        $this->scopedPdu = $request;

        return $this;
    }

    /**
     * Retrieve the context name from the scopedPdu (if it is set).
     *
     * @return string
     */
    public function getContextName(): string
    {
        return $this->scopedPdu
            ? $this->scopedPdu->getContextName()
            : '';
    }

    /**
     * {@inheritdoc}
     * @throws ProtocolException
     */
    public static function fromAsn1(AbstractType $asn1)
    {
        list($header, $securityParams, $pdu) = self::parseCommonElements($asn1);

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
