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

use FreeDSx\Snmp\Exception\EndOfWalkException;

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
     * @var Oid|null
     */
    protected $next;

    /**
     * @var int
     */
    protected $count = 0;

    /**
     * @var bool
     */
    protected $subtreeOnly;

    /**
     * @param SnmpClient $client
     * @param null|string $startAt
     * @param null|string $endAt
     * @param bool $subtreeOnly
     */
    public function __construct(SnmpClient $client, ?string $startAt = null, ?string $endAt = null, bool $subtreeOnly = true)
    {
        $this->client = $client;
        $this->startAt = $startAt ?? '1.3.6.1.2.1';
        $this->endAt = $endAt;
        $this->subtreeOnly = $subtreeOnly;
    }

    /**
     * Get the next OID in the walk.
     *
     * @return Oid
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     * @throws EndOfWalkException
     */
    public function next() : Oid
    {
        if ($this->isComplete()) {
            throw new EndOfWalkException('There are no more OIDs left in the walk.');
        }
        $this->current = $this->next ?? $this->getNextOid();
        $this->count++;
        if ($this->next) {
            $this->next = null;
        }

        return $this->current;
    }

    /**
     * @return bool
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     */
    public function isComplete() : bool
    {
        if ($this->current && $this->current->isEndOfMibView()) {
            return true;
        }
        if ($this->current && $this->current->getOid() === $this->endAt) {
            return true;
        }
        if ($this->subtreeOnly) {
            return $this->isEndOfSubtree();
        }

        return false;
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
     * @param bool $subtreeOnly
     * @return $this
     */
    public function subtreeOnly(bool $subtreeOnly = true)
    {
        $this->subtreeOnly = $subtreeOnly;

        return $this;
    }

    /**
     * Whether or not call the next method will produce more OIDs.
     *
     * @return bool
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
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
        $this->next = null;
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

    /**
     * @return Oid
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     */
    protected function getNextOid() : Oid
    {
        return $this->client->getNext($this->current ? $this->current->getOid() : $this->startAt)->first();
    }

    /**
     * @return bool
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     */
    protected function isEndOfSubtree() : bool
    {
        if ($this->next === null) {
            $this->next = $this->getNextOid();
        }

        return (substr($this->next->getOid(), 0, strlen($this->startAt)) !== $this->startAt);
    }
}
