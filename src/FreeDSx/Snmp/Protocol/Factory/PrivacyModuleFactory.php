<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Protocol\Factory;

use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Module\Privacy\AESPrivacyModule;
use FreeDSx\Snmp\Module\Privacy\DES3PrivacyModule;
use FreeDSx\Snmp\Module\Privacy\DESPrivacyModule;
use FreeDSx\Snmp\Module\Privacy\PrivacyModuleInterface;

/**
 * Gets the privacy module for a specific mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PrivacyModuleFactory
{
    /**
     * @var string[]
     */
    protected $modules;

    public function __construct()
    {
        $desModule = DESPrivacyModule::class;
        $des3Module = DES3PrivacyModule::class;
        $aesModule = AESPrivacyModule::class;

        foreach ([$desModule, $des3Module, $aesModule] as $module) {
            foreach (\call_user_func($module.'::supports') as $algorithm) {
                $this->modules[$algorithm] = $module;
            }
        }
    }

    /**
     * @param string $algorithm
     * @param int|null $boot
     * @return PrivacyModuleInterface
     */
    public function get(string $algorithm, ?int $boot = null) : PrivacyModuleInterface
    {
        if (!isset($this->modules[$algorithm])) {
            throw new InvalidArgumentException(sprintf(
                'The privacy mechanism "%s" is not recognized. Valid mechanisms are: %s',
                $algorithm,
                implode(', ', array_keys($this->modules))
            ));
        }

        return new $this->modules[$algorithm]($algorithm, $boot);
    }
}
