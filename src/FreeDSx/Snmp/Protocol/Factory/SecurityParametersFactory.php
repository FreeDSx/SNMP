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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;

/**
 * Construct the security parameters class based off the security model.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SecurityParametersFactory
{
    /**
     * @var array
     */
    protected static $map = [
        3 => UsmSecurityParameters::class,
    ];

    /**
     * @param int $securityModel
     * @param AbstractType $type
     * @return SecurityParametersInterface
     * @throws ProtocolException
     */
    public static function get(int $securityModel, AbstractType $type) : SecurityParametersInterface
    {
        if (!isset(self::$map[$securityModel])) {
            throw new ProtocolException(sprintf(
                'The security model %s is not recognized.',
                $securityModel
            ));
        }

        return \call_user_func(self::$map[$securityModel].'::fromAsn1', $type);
    }

    /**
     * @param string $class
     */
    public static function set(string $class) : void
    {
        if (!\in_array(SecurityParametersInterface::class, class_implements($class))) {
            throw new InvalidArgumentException(sprintf(
                'The security parameters "%s" must implement "%s", but it does not.',
                $class,
                SecurityParametersInterface::class
            ));
        }
        try {
            self::$map[(new $class())->getSecurityModel()] = $class;
        } catch (\Throwable $e) {
            throw new InvalidArgumentException(sprintf(
                'Unable to instantiate security paramters module "%s".',
                $class
            ));
        }
    }
}
