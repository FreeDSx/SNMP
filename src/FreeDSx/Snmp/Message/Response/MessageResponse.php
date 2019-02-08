<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message\Response;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\AbstractMessage;
use FreeDSx\Socket\PduInterface;

/**
 * Basically used as a factory from the message queue to determine what message response to instantiate.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MessageResponse extends AbstractMessage implements PduInterface
{
    /**
     * @var array
     */
    protected static $map = [
        0 => MessageResponseV1::class,
        1 => MessageResponseV2::class,
        3 => MessageResponseV3::class,
    ];

    public function __construct()
    {
        parent::__construct('');
    }

    /**
     * @param int $version
     * @param MessageResponseInterface $response
     */
    public static function setConstructor(int $version, MessageResponseInterface $response) : void
    {
        self::$map[$version] = get_class($response);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $asn1)
    {
        if (!($asn1 instanceof SequenceType && $asn1->getChild(0) instanceof IntegerType)) {
            throw new ProtocolException('The SNMP message is malformed.');
        }
        $version = $asn1->getChild(0)->getValue();

        if (!isset(self::$map[$version])) {
            throw new ProtocolException(sprintf(
                'The SNMP version %s is not supported.',
                $version
            ));
        }

        return \call_user_func(self::$map[$version].'::fromAsn1', $asn1);
    }
}
