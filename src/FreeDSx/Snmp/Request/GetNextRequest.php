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
 * Represents an GetNext request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class GetNextRequest extends Pdu implements RequestInterface
{
    use RequestTrait;

    protected const TAG = 1;

    /**
     * @var bool
     */
    protected $includeValues = false;

    /**
     * @param OidList ...$oids
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
        [$id, $errorStatus, $errorIndex, $oidList] = parent::getBaseElements($type);

        $nextRequest = new self($oidList);
        $nextRequest->id = $id;
        $nextRequest->errorStatus = $errorStatus;
        $nextRequest->errorIndex = $errorIndex;

        return $nextRequest;
    }
}
