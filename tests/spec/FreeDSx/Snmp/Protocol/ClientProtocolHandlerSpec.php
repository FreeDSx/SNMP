<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Protocol;

use FreeDSx\Snmp\Exception\ConnectionException;
use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Exception\RediscoveryNeededException;
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseV1;
use FreeDSx\Snmp\Message\Response\MessageResponseV2;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Module\SecurityModel\SecurityModelModuleInterface;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\ClientProtocolHandler;
use FreeDSx\Snmp\Protocol\Factory\SecurityModelModuleFactory;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Requests;
use FreeDSx\Snmp\Response\ReportResponse;
use FreeDSx\Snmp\Response\Response;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientProtocolHandlerSpec extends ObjectBehavior
{
    protected $options = [
        'transport' => 'udp',
        'use_tls' => false,
        'ssl_validate_cert' => true,
        'ssl_allow_self_signed' => null,
        'ssl_ca_cert' => null,
        'ssl_peer_name' => null,
        'port' => 161,
        'host' => 'localhost',
        'community' => 'public',
        'udp_retry' => 5,
        'timeout_connect' => 5,
        'timeout_read' => 10,
        'version' => 2,
        'engine_id' => '',
        'context_name' => '',
        'security_model' => 'usm',
        'use_auth' => false,
        'use_priv' => false,
        'auth_mech' => null,
        'priv_mech' => null,
        'priv_pwd' => null,
        'user' => null,
        'auth_pwd' => null,
        'id_min' => 1,
        'id_max' => 1,
    ];

    function let(Socket $socket, SnmpEncoder $encoder, Asn1MessageQueue $queue, SecurityModelModuleFactory $securityModelFactory, SecurityModelModuleInterface $securityModule)
    {
        $securityModelFactory->get(Argument::any())->willReturn($securityModule);
        $this->beConstructedWith($this->options, $socket, $encoder, $queue, $securityModelFactory);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientProtocolHandler::class);
    }

    function it_should_send_an_snmp_v1_request($encoder, $socket, $queue)
    {
        $encoder->encode(Argument::that(function ($type) {
            return $type->getChild(0)->getValue() === 0;
        }))->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn(new MessageResponseV1('foo', new Response(1)));

        $this->handle(Requests::get('1.2.3'), ['version' => 1])->shouldBeAnInstanceOf(MessageResponseV1::class);
    }

    function it_should_send_an_snmp_v2_request($encoder, $socket, $queue)
    {
        $encoder->encode(Argument::that(function ($type) {
            return $type->getChild(0)->getValue() === 1;
        }))->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn(new MessageResponseV2('foo', new Response(1)));

        $this->handle(Requests::get('1.2.3'), ['version' => 2])->shouldBeAnInstanceOf(MessageResponseV2::class);
    }

    function it_should_send_an_snmp_v3_request($encoder, $socket, $queue, $securityModule)
    {
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1)));
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );

        $encoder->encode(Argument::that(function ($type) {
            return $type->getChild(0)->getValue() === 3;
        }))->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn(new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1))));

        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->shouldBeCalled()->willReturn(true);
        $securityModule->getDiscoveryRequest(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleDiscoveryResponse(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($response);

        $this->handle(Requests::get('1.2.3'), ['version' => 3])->shouldBeAnInstanceOf(MessageResponseV3::class);
    }

    function it_should_send_the_message_to_the_security_model_if_authentication_is_specified($encoder, $socket, $queue, $securityModule)
    {
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1)));
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );

        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->shouldBeCalled()->willReturn(false);
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($response);

        $this->handle(Requests::get('1.2.3'), ['version' => 3, 'use_auth' => true, 'auth_pwd' => 'foobar123', 'auth_mech' => 'md5']);
    }

    function it_should_send_the_message_to_the_security_model_if_encryption_is_specified($encoder, $socket, $queue, $securityModule)
    {
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1)));
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );

        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->shouldBeCalled()->willReturn(false);
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($response);

        $this->handle(Requests::get('1.2.3'), ['version' => 3, 'use_priv' => true, 'use_auth' => true, 'auth_pwd' => 'foobar123', 'auth_mech' => 'md5', 'priv_pwd' => 'foobar123', 'priv_mech' => 'des']);
    }

    function it_should_send_a_disovery_request_for_the_security_model_if_needed($encoder, $socket, $queue, $securityModule)
    {
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1)));
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );

        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->shouldBeCalled()->willReturn(true);
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($response);
        $securityModule->getDiscoveryRequest(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleDiscoveryResponse(Argument::type(MessageRequestV3::class), Argument::type(MessageResponseV3::class), Argument::any())->shouldBeCalled()->willReturn($request);

        $this->handle(Requests::get('1.2.3'), ['version' => 3, 'use_priv' => true, 'use_auth' => true, 'auth_pwd' => 'foobar123', 'auth_mech' => 'md5', 'priv_pwd' => 'foobar123', 'priv_mech' => 'des']);
    }

    function it_should_send_an_snmp_v3_message_with_no_auth_no_priv($encoder, $socket, $queue, $securityModule)
    {
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1)));
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );

        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->shouldBeCalled()->willReturn(false);
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($response);

        $this->handle(Requests::get('1.2.3'), ['version' => 3, 'use_auth' => false, 'auth_mech' => 'md5']);
    }

    function it_should_not_try_to_get_a_response_when_sending_a_trap_v1($encoder, $socket, $queue)
    {
        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldNotBeCalled();

        $this->handle(Requests::trapV1('1.2.3','1.2.3.4', 1, 2, 1), ['version' => 1])->shouldBeNull();
    }

    function it_should_not_try_to_get_a_response_when_sending_a_trap_v2($encoder, $socket, $queue)
    {
        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldNotBeCalled();

        $this->handle(Requests::trap(1, '1.2.3'), ['version' => 2])->shouldBeNull();
    }

    function it_should_try_to_get_a_response_when_sending_an_inform_trap($encoder, $socket, $queue)
    {
        $response = new MessageResponseV2('public', new Response(1));

        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        $this->handle(Requests::inform(1, '1.2.3'), ['version' => 2])->shouldBeLike($response);
    }

    function it_should_throw_an_SnmpRequestException_if_the_error_status_is_not_zero($encoder, $queue)
    {
        $response = new MessageResponseV1('foo', new Response(1, 2, 1, new OidList(
            new Oid('1.2.3')
        )));

        $encoder->encode(Argument::any())->willReturn('foo');
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        $this->shouldThrow(new SnmpRequestException($response))->during('handle', [Requests::get('1.2.3'), ['version' => 1]]);
    }

    function it_should_throw_an_SnmpRequestException_if_the_request_id_is_not_expected($encoder, $queue)
    {
        $response = new MessageResponseV1('foo', new Response(2, 2, 1, new OidList(
            new Oid('1.2.3')
        )));

        $encoder->encode(Argument::any())->willReturn('foo');
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        $this->shouldThrow(new SnmpRequestException($response, 'Unexpected message ID received. Expected 1 but got 2.'))->during('handle', [Requests::get('1.2.3'), ['version' => 1]]);
    }

    function it_should_throw_an_SnmpRequestException_if_the_request_id_is_not_expected_during_snmp_v3($encoder, $queue, $socket, $securityModule)
    {
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(2)));
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );

        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->shouldBeCalled()->willReturn(false);
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($response);

        $this->shouldThrow(new SnmpRequestException($response, 'Unexpected message ID received. Expected 1 but got 2.'))->during('handle', [Requests::get('1.2.3'), ['version' => 3]]);
    }

    function it_should_throw_an_SnmpRequest_exception_if_the_request_id_is_not_expected_during_discovery_of_snmp_v3($encoder, $socket, $queue, $securityModule)
    {
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1)));
        $discoveryResponse = new MessageResponseV3(new MessageHeader(2), new ScopedPduResponse(new Response(2)));
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );

        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->willReturn($discoveryResponse, $response);

        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->shouldBeCalled()->willReturn(true);
        $securityModule->getDiscoveryRequest(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleDiscoveryResponse(Argument::any(), Argument::any(), Argument::any())->shouldNotBeCalled();
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->shouldNotBeCalled();
        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->shouldThrow(new SnmpRequestException($discoveryResponse, 'Unexpected message ID received. Expected 1 but got 2.'))->during('handle', [Requests::get('1.2.3'), ['version' => 3]]);
    }

    function it_should_perform_rediscovery_if_the_security_module_throws_a_rediscovery_exception($encoder, $socket, $queue, $securityModule)
    {
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1)));
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );

        $encoder->encode(Argument::that(function ($type) {
            return $type->getChild(0)->getValue() === 3;
        }))->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->willReturn(
            new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.2.0', 1))))),
            new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new Response(1)))
        );

        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->shouldBeCalled()->willReturn(false);
        $securityModule->getDiscoveryRequest(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleDiscoveryResponse(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleIncomingMessage(Argument::that(function ($message) {
            return $message->getResponse() instanceof ReportResponse;
        }), Argument::any())->shouldBeCalled(1)->willThrow(RediscoveryNeededException::class);
        $securityModule->handleIncomingMessage(Argument::that(function ($message) {
            return $message->getResponse() instanceof Response;
        }), Argument::any())->shouldBeCalled(1)->willReturn($response);

        $this->handle(Requests::get('1.2.3'), ['version' => 3])->shouldBeAnInstanceOf(MessageResponseV3::class);
    }

    function it_should_throw_an_SnmpRequestException_if_rediscovery_is_attempted_repeatedly($encoder, $socket, $queue, $securityModule)
    {
        $request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()))
        );
        $response = new MessageResponseV3(new MessageHeader(1), new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.2.0', 1)))));
        $encoder->encode(Argument::that(function ($type) {
            return $type->getChild(0)->getValue() === 3;
        }))->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->willReturn($response);
        /** @var SecurityModelModuleInterface $securityModule */
        $securityModule->isDiscoveryRequestNeeded(Argument::any(), Argument::any())->willReturn(false);
        $securityModule->getDiscoveryRequest(Argument::any(), Argument::any())->willReturn($request);
        $securityModule->handleDiscoveryResponse(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn($request);
        $securityModule->handleOutgoingMessage(Argument::any(), Argument::any())->willReturn($request);
        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->willThrow(new RediscoveryNeededException($response, 'foo'));

        $this->shouldThrow(SnmpRequestException::class)->during('handle', [Requests::get('1.2.3'), ['version' => 3]]);
    }

    function it_should_throw_an_SnmpRequestException_if_an_unhandled_Report_PDU_is_received($encoder, $socket, $queue)
    {
        $response = new MessageResponseV2('foo', new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.2.3', 1))));
        $encoder->encode(Argument::that(function ($type) {
            return $type->getChild(0)->getValue() === 1;
        }))->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn($response);

        $this->shouldThrow(new SnmpRequestException($response, 'Received a report PDU with the OID(s): 1.2.3'))->during('handle', [Requests::get('1.2.3'), ['version' => 2]]);
    }

    function it_should_throw_an_SnmpRequestException_if_a_report_response_is_received_with_snmp_v1($encoder, $socket, $queue)
    {
        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willReturn(new MessageResponseV1('foo', new ReportResponse(1)));

        $this->shouldThrow(SnmpRequestException::class)->during('handle', [Requests::get('1.2.3'), ['version' => 1]]);
    }

    function it_should_throw_an_InvalidArgumentException_if_a_trap_v2_is_sent_with_snmp_v1()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('handle', [Requests::trap(1, '1.2'), ['version' => 1]]);
    }

    function it_should_throw_an_InvalidArgumentException_if_an_inform_is_sent_with_snmp_v1()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('handle', [Requests::inform(1, '1.2'), ['version' => 1]]);
    }

    function it_should_throw_an_InvalidArgumentException_if_a_getbulk_is_sent_with_snmp_v1()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('handle', [Requests::getBulk(1, 2, '1.2'), ['version' => 1]]);
    }

    function it_should_throw_an_SnmpConnectionException_if_the_request_has_a_connection_issue_with_the_socket($encoder, $socket)
    {
        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled()->willThrow(\FreeDSx\Socket\Exception\ConnectionException::class);

        $this->shouldThrow(ConnectionException::class)->during('handle', [Requests::get('1.2.3'), ['version' => 2]]);
    }

    function it_should_throw_an_SnmpConnectionException_if_the_request_has_a_connection_issue_with_the_queue($encoder, $socket, $queue)
    {
        $encoder->encode(Argument::any())->shouldBeCalled()->willReturn('foo');
        $socket->write('foo')->shouldBeCalled();
        $queue->getMessage()->shouldBeCalled()->willThrow(\FreeDSx\Socket\Exception\ConnectionException::class);

        $this->shouldThrow(ConnectionException::class)->during('handle', [Requests::get('1.2.3'), ['version' => 2]]);
    }
}
