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

use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Module\SecurityModel\SecurityModelModuleInterface;
use FreeDSx\Snmp\Module\SecurityModel\UserSecurityModelModule;

/**
 * Given a security model integer, get the class that handles its logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SecurityModelModuleFactory
{
    /**
     * @var array
     */
    protected $map = [];

    /**
     * @var SecurityModelModuleInterface[]
     */
    protected $loaded = [];

    public function __construct()
    {
        $module = UserSecurityModelModule::class;
        $this->map[\call_user_func($module.'::supports')] = $module;
    }

    /**
     * @param int $securityModel
     * @return SecurityModelModuleInterface
     * @throws ProtocolException
     */
    public function get(int $securityModel) : SecurityModelModuleInterface
    {
        if (!isset($this->map[$securityModel])) {
            throw new ProtocolException(sprintf(
               'The security model %s is not supported. Supported security models are: %s',
               $securityModel,
               implode(', ', array_keys($this->map))
            ));
        }
        if (!isset($this->loaded[$securityModel])) {
            $this->loaded[$securityModel] = new $this->map[$securityModel]();
        }

        return $this->loaded[$securityModel];
    }
}
