<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Module\SecurityModel\Usm;


/**
 * Holds some time logic related to synchronization for an engine.
 *
 * RFC 3414.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TimeSync
{
    /**
     * @var int
     */
    protected $engineBoot;

    /**
     * @var int
     */
    protected $engineTime;

    /**
     * @var \DateTime
     */
    protected $whenSynced;

    /**
     * @param int $engineBoot
     * @param int $engineTime
     * @param \DateTime|null $whenSynced
     */
    public function __construct(int $engineBoot, int $engineTime, ?\DateTime $whenSynced = null)
    {
        $this->engineBoot = $engineBoot;
        $this->engineTime = $engineTime;
        $this->whenSynced = $whenSynced ?: new \DateTime();
    }

    /**
     * @return int
     */
    public function getEngineBoot() : int
    {
        return $this->engineBoot;
    }

    /**
     * @return int
     */
    public function getEngineTime(): int
    {
        return $this->engineTime;
    }

    /**
     * @return \DateTime
     */
    public function getWhenSynced() : \DateTime
    {
        return $this->whenSynced;
    }
}
