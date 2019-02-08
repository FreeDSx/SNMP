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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;

/**
 * Represents a VarBindList.
 *
 * VarBindList ::= SEQUENCE (SIZE (0..max-bindings)) OF VarBind
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OidList implements \IteratorAggregate, \Countable, ProtocolElementInterface
{
    /**
     * @var Oid[]
     */
    protected $oids;

    /**
     * @param Oid ...$oids
     */
    public function __construct(Oid ...$oids)
    {
        $this->oids = $oids;
    }

    /**
     * Add one or more Oid to the list.
     *
     * @param Oid ...$oids
     * @return $this
     */
    public function add(Oid ...$oids)
    {
        foreach ($oids as $oid) {
            $this->oids[] = $oid;
        }

        return $this;
    }

    /**
     * @param string $oid
     * @return bool
     */
    public function has(string $oid) : bool
    {
        foreach ($this->oids as $oidObj) {
            if ($oidObj->getOid() === $oid) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the Oid with a specific OID.
     *
     * @param string $oid
     * @return Oid|null
     */
    public function get(string $oid) : ?Oid
    {
        foreach ($this->oids as $varBind) {
            if ($oid === $varBind->getOid()) {
                return $varBind;
            }
        }

        return null;
    }

    /**
     * Get the Oid for a specific index (if it exists). The index for variable bindings starts at 1.
     *
     * @param int $index
     * @return Oid|null
     */
    public function index(int $index) : ?Oid
    {
        return isset($this->oids[$index - 1]) ? $this->oids[$index - 1] : null;
    }

    /**
     * Get the first Oid in the list.
     *
     * @return Oid|null
     */
    public function first() : ?Oid
    {
        $oid = \reset($this->oids);

        return $oid ?: null;
    }

    /**
     * Get the last oid in the list.
     *
     * @return Oid|null
     */
    public function last() : ?Oid
    {
        $oid = \end($this->oids);
        \reset($this->oids);

        return $oid ?: null;
    }

    /**
     * @return Oid[]
     */
    public function toArray() : array
    {
        return $this->oids;
    }

    /**
     * @return \ArrayIterator|\Traversable
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->oids);
    }

    /**
     * @return int
     */
    public function count()
    {
        return \count($this->oids);
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        $varBinds = [];

        foreach ($this->oids as $varBind) {
            $varBinds[] = $varBind->toAsn1();
        }

        return Asn1::sequenceOf(...$varBinds);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'The VarBindList must be a sequence. Got instance of: %s',
                get_class($type)
            ));
        }

        $oids = [];
        foreach ($type as $varBind) {
            $oids[] = Oid::fromAsn1($varBind);
        }

        return new self(...$oids);
    }
}
