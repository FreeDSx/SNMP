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
use FreeDSx\Snmp\Module\Authentication\AuthenticationModuleInterface;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModule;

/**
 * Gets the authentication module to use for a specific authentication mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AuthenticationModuleFactory
{
    /**
     * @var AuthenticationModuleInterface[]
     */
    protected $modules;

    public function __construct()
    {
        $module = AuthenticationModule::class;

        foreach (\call_user_func($module.'::supports') as $algorithm) {
            $this->modules[$algorithm] = $module;
        }
    }

    /**
     * @param string $algorithm
     * @return AuthenticationModuleInterface
     */
    public function get(string $algorithm) : AuthenticationModuleInterface
    {
        if (!isset($this->modules[$algorithm])) {
            throw new InvalidArgumentException(sprintf(
                'The authentication mechanism "%s" is not recognized. Valid mechanisms are: %s',
                $algorithm,
                implode(', ', array_keys($this->modules))
            ));
        }

        return new $this->modules[$algorithm]($algorithm);
    }
}
