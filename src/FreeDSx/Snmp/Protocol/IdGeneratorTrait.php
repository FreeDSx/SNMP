<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Protocol;

/**
 * ID generator logic is used in a few different spots. Isolate it to this trait.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait IdGeneratorTrait
{
    /**
     * The max value for a request id.
     *
     * @var int
     */
    protected static $maxId = 2147483647;

    /**
     * The minimum value for a request id.
     *
     * @var int
     */
    protected static $minId = -214783648;

    /**
     * @param int|null $min
     * @param int|null $max
     * @return int
     * @throws \Exception
     */
    protected function generateId(?int $min = null, ?int $max = null) : int
    {
        $min = $this->options['id_min'] ?? $min ?? self::$minId;
        $max = $this->options['id_max'] ?? $max ?? self::$maxId;

        return \random_int($min, $max);
    }
}
