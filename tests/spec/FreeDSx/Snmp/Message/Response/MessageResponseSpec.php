<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Message\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Response\MessageResponse;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\Response\MessageResponseV1;
use FreeDSx\Snmp\Message\Response\MessageResponseV2;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Response\Response;
use FreeDSx\Snmp\Response\ResponseInterface;
use FreeDSx\Socket\PduInterface;
use PhpSpec\ObjectBehavior;

class MessageResponseSpec extends ObjectBehavior
{
    protected $factoryV1;

    protected $factoryV2;

    protected $factoryV3;

    function let()
    {
        $this->factoryV1 = new class implements MessageResponseInterface {
            public function getResponse(): ResponseInterface{}
            public function getVersion(): int{}
            public function toAsn1(): AbstractType{}
            public static function fromAsn1(AbstractType $asn1)
            {
                return new self();
            }
        };
        $this->factoryV2 = new class implements MessageResponseInterface {
            public function getResponse(): ResponseInterface{}
            public function getVersion(): int{}
            public function toAsn1(): AbstractType{}
            public static function fromAsn1(AbstractType $asn1)
            {
                return new self();
            }
        };
        $this->factoryV3 = new class implements MessageResponseInterface {
            public function getResponse(): ResponseInterface{}
            public function getVersion(): int{}
            public function toAsn1(): AbstractType{}
            public static function fromAsn1(AbstractType $asn1)
            {
                return new self();
            }
        };

        $this::setConstructor(0, $this->factoryV1);
        $this::setConstructor(1, $this->factoryV2);
        $this::setConstructor(3, $this->factoryV3);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(MessageResponse::class);
    }

    function it_should_implement_the_pdu_interface()
    {
        $this->shouldImplement(PduInterface::class);
    }

    function it_should_construct_a_snmp_v1_response_from_asn1()
    {
        $message = new MessageResponseV1('foo', new Response(0));

        $this::fromAsn1($message->toAsn1())->shouldReturnAnInstanceOf(get_class($this->factoryV1));
    }

    function it_should_construct_a_snmp_v2_response_from_asn1()
    {
        $message = new MessageResponseV2('foo', new Response(0));

        $this::fromAsn1($message->toAsn1())->shouldReturnAnInstanceOf(get_class($this->factoryV2));
    }

    function it_should_construct_a_snmp_v3_response_from_asn1()
    {
        $message = new MessageResponseV3(
            new MessageHeader(1),
            new ScopedPduResponse(new Response(0))
        );

        $this::fromAsn1($message->toAsn1())->shouldReturnAnInstanceOf(get_class($this->factoryV3));
    }

    function it_should_throw_an_exception_for_an_unrecognized_snmp_version_request()
    {
        $message = Asn1::sequence(
            Asn1::integer(99),
            Asn1::integer(99),
            Asn1::integer(99)
        );

        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [$message]);
    }

    function it_should_validate_the_basic_message_response_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [
            Asn1::sequence(
                Asn1::octetString('')
            )
        ]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [
            Asn1::octetString('')
        ]);
    }
}
