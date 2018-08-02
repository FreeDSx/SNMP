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
 * Represents a GetBulk Request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class GetBulkRequest extends Pdu implements RequestInterface
{
    use RequestTrait;

    protected const TAG = 5;

    /**
     * @var bool
     */
    protected $includeValues = false;

    /**
     * @param int $maxRepetitions
     * @param int $nonRepeaters
     * @param OidList $oids
     */
    public function __construct(int $maxRepetitions, int $nonRepeaters, OidList $oids)
    {
        parent::__construct(0, $nonRepeaters, $maxRepetitions, $oids);
    }

    /**
     * @return int
     */
    public function getMaxRepetitions() : int
    {
        return $this->errorIndex;
    }

    /**
     * @param int $maxRepetitions
     * @return $this
     */
    public function setMaxRepetitions(int $maxRepetitions)
    {
        $this->errorIndex = $maxRepetitions;

        return $this;
    }

    /**
     * @return int
     */
    public function getNonRepeaters() : int
    {
        return $this->errorStatus;
    }

    /**
     * @param int $nonRepeaters
     * @return $this
     */
    public function setNonRepeaters(int $nonRepeaters)
    {
        $this->errorStatus = $nonRepeaters;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        list($id, $errorStatus, $errorIndex, $oidList) = parent::getBaseElements($type);

        $bulkRequest = new self(
            $errorIndex,
            $errorStatus,
            $oidList
        );
        $bulkRequest->id = $id;

        return $bulkRequest;
    }
}
