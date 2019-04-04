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
use function count;

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
     * @var Oid[]
     */
    protected $next = [];

    /**
     * @var int
     */
    protected $count = 0;

    /**
     * @var bool
     */
    protected $subtreeOnly;

    /**
     * @var null|bool
     */
    protected $useGetBulk;

    /**
     * @var int
     */
    protected $maxRepetitions = 100;

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
        if (count($this->next) === 0) {
            $this->next = $this->getNextOid();
        }
        $this->throwIfNoNextOids();
        $this->current = \array_shift($this->next);
        $this->count++;

        return $this->current;
    }

    /**
     * An alias of the next() method.
     *
     * @return Oid
     * @throws EndOfWalkException
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     */
    public function getOid() : Oid
    {
        return $this->next();
    }

    /**
     * @return bool
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     * @throws EndOfWalkException
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
     * @throws EndOfWalkException
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
        $this->next = [];
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
     * Explicitly set whether or not to use the GetBulk method for OID retrieval in a SNMPv2 / SNMPv3 context. If the
     * SNMP version is set to v1 then it will only use GetNext regardless.
     *
     * By default GetBulk is used if the SNMP version supports it.
     *
     * @param bool $useGetBulk
     * @return $this
     */
    public function useGetBulk(bool $useGetBulk)
    {
        $this->useGetBulk = $useGetBulk;

        return $this;
    }

    /**
     * Use a specific number of max repetitions (applicable if using GetBulk requests). This is the number of OIDs that
     * a GetBulk will request to return at once. Depending on the remote host, this might need to be toggled.
     *
     * @param int $maxRepetitions
     * @return $this
     */
    public function maxRepetitions(int $maxRepetitions)
    {
        $this->maxRepetitions = $maxRepetitions;

        return $this;
    }

    /**
     * @return Oid[]
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     */
    protected function getNextOid() : array
    {
        $currentOid = $this->current ? $this->current->getOid() : $this->startAt;

        if (($this->useGetBulk === null || $this->useGetBulk) && $this->client->getOptions()['version'] >= 2) {
            return $this->client->getBulk($this->maxRepetitions, 0, $currentOid)->toArray();
        } else {
            return $this->client->getNext($currentOid)->toArray();
        }
    }

    /**
     * @return bool
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     * @throws EndOfWalkException
     */
    protected function isEndOfSubtree() : bool
    {
        if (count($this->next) === 0) {
            $this->next = $this->getNextOid();
        }
        $this->throwIfNoNextOids();

        return (\substr($this->next[0]->getOid(), 0, \strlen($this->startAt)) !== $this->startAt);
    }

    /**
     * @throws EndOfWalkException
     */
    protected function throwIfNoNextOids() : void
    {
        if (count($this->next) === 0) {
            throw new EndOfWalkException('There are no more OIDs left in the walk.');
        }
    }
}
