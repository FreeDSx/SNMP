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
use FreeDSx\Snmp\Protocol\Factory\RequestFactory;
use FreeDSx\Snmp\Request\RequestInterface;

/**
 * Represents a Scoped PDU request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ScopedPduRequest extends ScopedPdu
{
    /**
     * @param null|EngineId $contextEngineId
     * @param string $contextName
     * @param RequestInterface $request
     */
    public function __construct(RequestInterface $request, ?EngineId $contextEngineId = null, string $contextName = '')
    {
        parent::__construct($request, $contextEngineId, $contextName);
    }

    /**
     * @param string $contextName
     * @return $this
     */
    public function setContextName(string $contextName)
    {
        $this->contextName = $contextName;

        return $this;
    }

    /**
     * @param null|EngineId $contextEngineId
     * @return $this
     */
    public function setContextEngineId(?EngineId $contextEngineId)
    {
        $this->contextEngineId = $contextEngineId;

        return $this;
    }

    /**
     * @return Pdu
     */
    public function getRequest() : RequestInterface
    {
        return $this->pdu;
    }

    /**
     * @param RequestInterface $request
     * @return $this
     */
    public function setRequest(RequestInterface $request)
    {
        $this->pdu = $request;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        list($engineId, $contextName, $pdu) = self::parseBaseElements($type);

        return new self(
            RequestFactory::get($pdu),
            $engineId,
            $contextName
        );
    }
}
