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
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\AbstractMessage;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Protocol\Factory\ResponseFactory;

/**
 * Represents a SNMPv2 Message Response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageResponseV2 extends AbstractMessage implements MessageResponseInterface
{
    protected const VERSION = 1;

    use MessageResponseTrait;

    /**
     * @param string $community
     * @param Pdu $response
     */
    public function __construct(string $community, Pdu $response)
    {
        $this->pdu = $response;
        parent::__construct($community);
    }

    /**
     * {@inheritdoc}
     * @throws ProtocolException
     */
    public static function fromAsn1(AbstractType $asn1): MessageResponseV2
    {
        $pdu = $asn1->getChild(2);
        if ($pdu == null) {
            throw new ProtocolException('The response is malformed.');
        }

        return new static(
            static::parseCommunity($asn1),
            ResponseFactory::get($pdu)
        );
    }
}
