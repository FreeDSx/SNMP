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
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Request\GetBulkRequest;
use FreeDSx\Snmp\Request\GetNextRequest;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Request\SetRequest;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;

/**
 * Resolves specific ASN.1 app tags to their Request classes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RequestFactory
{
    /**
     * @var array
     */
    protected static $map = [
        0 => GetRequest::class,
        1 => GetNextRequest::class,
        3 => SetRequest::class,
        4 => TrapV1Request::class,
        5 => GetBulkRequest::class,
        6 => InformRequest::class,
        7 => TrapV2Request::class,
    ];

    /**
     * @param AbstractType $type
     * @return RequestInterface
     * @throws ProtocolException
     */
    public static function get(AbstractType $type) : RequestInterface
    {
        if (!isset(self::$map[$type->getTagNumber()])) {
            throw new ProtocolException(sprintf(
                'The PDU number %s is not recognized.',
                $type->getTagNumber()
            ));
        }

        return \call_user_func(self::$map[$type->getTagNumber()].'::fromAsn1', $type);
    }
}
