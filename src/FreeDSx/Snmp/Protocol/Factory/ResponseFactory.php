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
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Response\Response;
use FreeDSx\Snmp\Response\ReportResponse;

/**
 * Maps the PDU type to the response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ResponseFactory
{
    /**
     * @var array<int, class-string>
     */
    protected static $map = [
        2 => Response::class,
        8 => ReportResponse::class,
    ];

    /**
     * @param AbstractType $type
     * @return Pdu
     * @throws ProtocolException
     */
    public static function get(AbstractType $type) : Pdu
    {
        if (!isset(self::$map[$type->getTagNumber()])) {
            throw new ProtocolException(sprintf(
                'The PDU number %s is not recognized.',
                $type->getTagNumber()
            ));
        }

        return \call_user_func(
            self::$map[$type->getTagNumber()].'::fromAsn1',
            $type
        );
    }
}
