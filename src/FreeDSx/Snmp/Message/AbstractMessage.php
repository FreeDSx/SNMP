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
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Response\ResponseInterface;
use FreeDSx\Socket\PduInterface;

/**
 * Represents a base for an SNMPv1/v2 Message.
 *
 * Message ::=
 *     SEQUENCE {
 *         version        -- version-1 for this RFC
 *             INTEGER {
 *                 version-1(0)
 *             },
 *
 *         community      -- community name
 *             OCTET STRING,
 *
 *         data           -- e.g., PDUs if trivial
 *             ANY        -- authentication is being used
 *     }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class AbstractMessage implements PduInterface
{
    protected const VERSION = null;

    /**
     * @var string
     */
    protected $community;

    /**
     * @var Pdu|RequestInterface|ResponseInterface
     */
    protected $pdu;

    /**
     * @param string $community
     */
    public function __construct(string $community)
    {
        $this->community = $community;
    }

    public function getCommunity() : string
    {
        return $this->community;
    }

    /**
     * @return int
     */
    public function getVersion() : int
    {
        return static::VERSION;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        return Asn1::sequence(
            Asn1::integer(static::VERSION),
            Asn1::octetString($this->community),
            $this->pdu->toAsn1()
        );
    }

    /**
     * @param AbstractType $asn1
     * @return string
     * @throws ProtocolException
     */
    protected static function parseCommunity(AbstractType $asn1)
    {
        if (!($asn1 instanceof SequenceType && count($asn1->getChildren()) === 3)) {
            throw new ProtocolException('The SNMP message must be a sequence with at least 3 elements.');
        }
        $version = $asn1->getChild(0);
        if (!($version instanceof IntegerType && $version->getValue() === static::VERSION)) {
            throw new ProtocolException(sprintf(
                'Expected SNMP version %s, got %s.',
                static::VERSION,
                $version->getValue()
            ));
        }
        $community = $asn1->getChild(1);
        if (!$community instanceof OctetStringType) {
            throw new ProtocolException(sprintf(
                'Expected an octet string type for the community, got %s.',
                get_class($community)
            ));
        }

        return $community->getValue();
    }
}
