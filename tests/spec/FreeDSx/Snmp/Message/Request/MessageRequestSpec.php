<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Message\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequest;
use FreeDSx\Snmp\Message\Request\MessageRequestV1;
use FreeDSx\Snmp\Message\Request\MessageRequestV2;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Socket\PduInterface;
use PhpSpec\ObjectBehavior;

class MessageRequestSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(MessageRequest::class);
    }

    function it_should_implement_the_pdu_interface()
    {
        $this->shouldImplement(PduInterface::class);
    }

    function it_should_construct_a_snmp_v1_request_from_asn1()
    {
        $encoder = new SnmpEncoder();

        $pdu = '';
        foreach ((new GetRequest(new OidList()))->toAsn1() as $child) {
            $pdu .= $encoder->encode($child);
        }

        $asn1 = Asn1::sequence(
            Asn1::integer(0),
            Asn1::octetString('foo'),
            Asn1::context(0, new IncompleteType($pdu))->setIsConstructed(true)

        );

        $this::fromAsn1($asn1)->shouldBeAnInstanceOf(MessageRequestV1::class);
    }

    function it_should_construct_a_snmp_v2_request_from_asn1()
    {
        $encoder = new SnmpEncoder();

        $pdu = '';
        foreach ((new GetRequest(new OidList()))->toAsn1() as $child) {
            $pdu .= $encoder->encode($child);
        }

        $asn1 = Asn1::sequence(
            Asn1::integer(1),
            Asn1::octetString('foo'),
            Asn1::context(0, new IncompleteType($pdu))->setIsConstructed(true)

        );

        $this::fromAsn1($asn1)->shouldReturnAnInstanceOf(MessageRequestV2::class);
    }

    function it_should_construct_a_snmp_v3_request_from_asn1()
    {
        $encoder = new SnmpEncoder();

        $pdu = '';
        foreach ((new GetRequest(new OidList()))->toAsn1() as $child) {
            $pdu .= $encoder->encode($child);
        }

        $asn1 = Asn1::sequence(
            Asn1::integer(3),
            (new MessageHeader(0, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3))->toAsn1(),
            Asn1::octetString((new SnmpEncoder())->encode((new UsmSecurityParameters())->toAsn1())),
            Asn1::sequence(
                Asn1::octetString(''),
                Asn1::octetString(''),
                Asn1::context(0, new IncompleteType($pdu))->setIsConstructed(true)
            )
        );

        $this::fromAsn1($asn1)->shouldReturnAnInstanceOf(MessageRequestV3::class);
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

    function it_should_validate_the_basic_message_request_asn1()
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
