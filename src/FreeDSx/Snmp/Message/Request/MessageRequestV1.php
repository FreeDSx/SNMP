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
use FreeDSx\Snmp\Message\AbstractMessage;
use FreeDSx\Snmp\Protocol\Factory\RequestFactory;
use FreeDSx\Snmp\Request\RequestInterface;

/**
 * Represents a SNMPv1 Message Request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageRequestV1 extends AbstractMessage implements MessageRequestInterface
{
    use MessageRequestTrait;

    protected const VERSION = 0;

    /**
     * @param string $community
     * @param RequestInterface $request
     */
    public function __construct(string $community, RequestInterface $request)
    {
        $this->pdu = $request;
        parent::__construct($community);
    }

    /**
     * @param string $community
     * @return $this
     */
    public function setCommunity(string $community)
    {
        $this->community = $community;

        return $this;
    }

    /**
     * @param AbstractType $asn1
     * @return MessageRequestV1
     * @throws \FreeDSx\Snmp\Exception\ProtocolException
     */
    public static function fromAsn1(AbstractType $asn1)
    {
        return new static(
            static::parseCommunity($asn1),
            RequestFactory::get($asn1->getChild(2))
        );
    }
}
