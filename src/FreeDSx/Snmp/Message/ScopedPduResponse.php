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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Snmp\Protocol\Factory\ResponseFactory;
use FreeDSx\Snmp\Response\ResponseInterface;

/**
 * Represents a Scoped PDU response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ScopedPduResponse extends ScopedPdu
{
    /**
     * @param ResponseInterface $response
     * @param null|EngineId $contextEngineId
     * @param string $contextName
     */
    public function __construct(ResponseInterface $response, ?EngineId $contextEngineId = null, string $contextName = '')
    {
        parent::__construct($response, $contextEngineId, $contextName);
    }

    /**
     * @return Pdu|ResponseInterface
     */
    public function getResponse() : ResponseInterface
    {
        return $this->pdu;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        list($engineId, $contextName, $pdu) = self::parseBaseElements($type);

        return new self(
            ResponseFactory::get($pdu),
            $engineId,
            $contextName
        );
    }
}
