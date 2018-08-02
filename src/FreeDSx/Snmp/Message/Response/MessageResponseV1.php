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
use FreeDSx\Snmp\Message\AbstractMessage;
use FreeDSx\Snmp\Protocol\Factory\ResponseFactory;
use FreeDSx\Snmp\Response\ResponseInterface;

/**
 * Represents a SNMPv1 Message Response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageResponseV1 extends AbstractMessage implements MessageResponseInterface
{
    protected const VERSION = 0;

    use MessageResponseTrait;

    /**
     * @param string $community
     * @param ResponseInterface $response
     */
    public function __construct(string $community, ResponseInterface $response)
    {
        $this->pdu = $response;
        parent::__construct($community);
    }

    /**
     * @param AbstractType $asn1
     * @return MessageResponseV1
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Snmp\Exception\ProtocolException
     */
    public static function fromAsn1(AbstractType $asn1)
    {
        return new static(
            static::parseCommunity($asn1),
            ResponseFactory::get($asn1->getChild(2))
        );
    }
}
