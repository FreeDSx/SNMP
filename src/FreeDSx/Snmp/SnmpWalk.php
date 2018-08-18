<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp;

/**
 * Provides a simple API to perform an SNMP walk.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SnmpWalk
{
    /**
     * @var SnmpClient
     */
    protected $client;

    /**
     * @var string
     */
    protected $startAt;

    /**
     * @var null|string
     */
    protected $endAt;

    /**
     * @var Oid|null
     */
    protected $current;

    /**
     * @var int
     */
    protected $count = 0;

    /**
     * @param SnmpClient $client
     * @param null|string $startAt
     * @param null|string $endAt
     */
    public function __construct(SnmpClient $client, ?string $startAt = null, ?string $endAt = null)
    {
        $this->client = $client;
        $this->startAt = $startAt ?? '1.3.6.1.2.1';
        $this->endAt = $endAt;
    }

    /**
     * Get the next OID in the walk.
     *
     * @return Oid
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     */
    public function next() : Oid
    {
        $this->current = $this->client->getNext($this->current ? $this->current->getOid() : $this->startAt)->first();
        $this->count++;

        return $this->current;
    }

    /**
     * @return bool
     */
    public function isComplete() : bool
    {
        if (!$this->current) {
            return false;
        }

        if ($this->current->getOid() === $this->endAt) {
            return true;
        }

        return $this->current->isEndOfMibView();
    }

    /**
     * Get the number of OIDs walked.
     *
     * @return int
     */
    public function count() : int
    {
        return $this->count;
    }

    /**
     * Whether or not call the next method will produce more OIDs.
     *
     * @return bool
     */
    public function hasOids() : bool
    {
        return !$this->isComplete();
    }

    /**
     * Set the walk back to the original start OID.
     *
     * @return $this
     */
    public function restart()
    {
        $this->current = null;
        $this->count = 0;

        return $this;
    }

    /**
     * Set the walk to begin at a specific OID.
     *
     * @param string $oid
     * @return $this
     */
    public function startAt(string $oid)
    {
        $this->startAt = $oid;

        return $this;
    }

    /**
     * Set the walk to end at a specific OID.
     *
     * @param string $oid
     * @return $this
     */
    public function endAt(string $oid)
    {
        $this->endAt = $oid;

        return $this;
    }

    /**
     * Set the walk to skip to a specific OID, regardless of where it is currently.
     *
     * @param string $oid
     * @return $this
     */
    public function skipTo(string $oid)
    {
        $this->current = new Oid($oid);

        return $this;
    }
}
