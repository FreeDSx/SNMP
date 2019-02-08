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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;

/**
 * Represents a Scoped PDU. RFC 3412, Section 6.
 *
 * SEQUENCE {
 *     contextEngineID  OCTET STRING,
 *     contextName      OCTET STRING,
 *     data             ANY -- e.g., PDUs as defined in [RFC3416]
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class ScopedPdu implements ProtocolElementInterface
{
    /**
     * @var null|EngineId
     */
    protected $contextEngineId;

    /**
     * @var string
     */
    protected $contextName;

    /**
     * @var Pdu
     */
    protected $pdu;

    /**
     * @param Pdu $pdu
     * @param null|EngineId $contextEngineId
     * @param string $contextName
     */
    public function __construct(Pdu $pdu, ?EngineId $contextEngineId = null, $contextName = '')
    {
        $this->pdu = $pdu;
        $this->contextEngineId = $contextEngineId;
        $this->contextName = $contextName;
    }

    /**
     * @return string
     */
    public function getContextName() : string
    {
        return $this->contextName;
    }

    /**
     * @return string
     */
    public function getContextEngineId() : ?EngineId
    {
        return $this->contextEngineId;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        $engineId = ($this->contextEngineId === null) ? '' : $this->contextEngineId->toBinary();

        return Asn1::sequence(
            Asn1::octetString($engineId),
            Asn1::octetString($this->contextName),
            $this->pdu->toAsn1()
        );
    }

    /**
     * @param AbstractType $type
     * @return array
     * @throws ProtocolException
     */
    protected static function parseBaseElements(AbstractType $type) : array
    {
        if (!($type instanceof SequenceType && \count($type->getChildren()) === 3)) {
            throw new ProtocolException('Expected the scoped PDU to be a sequence with exactly 3 elements.');
        }
        $engineId = $type->getChild(0);
        $contextName = $type->getChild(1);
        $pdu = $type->getChild(2);

        if (!$engineId instanceof OctetStringType) {
            throw new ProtocolException(sprintf(
               'Expected the engine id to be an octet string, got %s',
               get_class($engineId)
            ));
        }
        if (!$contextName instanceof OctetStringType) {
            throw new ProtocolException(sprintf(
                'Expected the context name to be an octet string, got %s',
                get_class($contextName)
            ));
        }
        $engineId = ($engineId->getValue() === '') ? null : EngineId::fromBinary($engineId->getValue());

        return [$engineId, $contextName->getValue(), $pdu];
    }
}
