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
 * Represents a SetRequest.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SetRequest extends Pdu implements RequestInterface
{
    use RequestTrait;

    protected const TAG = 3;

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

        $setRequest = new self($oidList);
        $setRequest->id = $id;
        $setRequest->errorStatus = $errorStatus;
        $setRequest->errorIndex = $errorIndex;

        return $setRequest;
    }
}
