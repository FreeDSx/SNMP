<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Request;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\OidList;

/**
 * Represents a Get Request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class GetRequest extends Pdu implements RequestInterface
{
    use RequestTrait;

    protected const TAG = 0;

    /**
     * @var bool
     */
    protected $includeValues = false;

    /**
     * @param OidList $oids
     */
    public function __construct(OidList $oids)
    {
        parent::__construct(0, 0, 0, $oids);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        list($id, $errorStatus, $errorIndex, $oidList) = parent::getBaseElements($type);

        $getRequest = new self($oidList);
        $getRequest->id = $id;
        $getRequest->errorStatus = $errorStatus;
        $getRequest->errorIndex = $errorIndex;

        return $getRequest;
    }
}
