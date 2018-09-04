<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp;

use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Protocol\ClientProtocolHandler;
use FreeDSx\Snmp\Request\GetBulkRequest;
use FreeDSx\Snmp\Request\GetNextRequest;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\SetRequest;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Response\Response;
use FreeDSx\Snmp\SnmpClient;
use FreeDSx\Snmp\SnmpWalk;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SnmpClientSpec extends ObjectBehavior
{
    protected $response;

    function let(ClientProtocolHandler $handler)
    {
        $this->response = new MessageResponseV3(
            new MessageHeader(1),
            new ScopedPduResponse(new Response(0, 0, 0, new OidList(Oid::fromCounter('1.2.3', 1))))
        );
        $this->beConstructedWith(['_protocol_handler' => $handler]);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SnmpClient::class);
    }

    function it_should_send_a_get_bulk_request($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new GetBulkRequest(1, 1, new OidList(new Oid('1.2.3'))), Argument::any())
            ->shouldBeCalled()->willReturn($this->response);

        $this->getBulk(1, 1, '1.2.3');
    }


    function it_should_send_a_get_request($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new GetRequest(new OidList(new Oid('1.2.3'))), Argument::any())
            ->shouldBeCalled()->willReturn($this->response);

        $this->get('1.2.3');
    }

    function it_should_send_a_get_next_request($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new GetNextRequest(new OidList(new Oid('1.2.3'))), Argument::any())
            ->shouldBeCalled()->willReturn($this->response);

        $this->getNext('1.2.3');
    }

    function it_should_send_a_set_request($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new SetRequest(new OidList(new Oid('1.2.3', OidValues::counter(1)))), Argument::any())
            ->shouldBeCalled()->willReturn($this->response);

        $this->set(Oid::fromCounter('1.2.3', 1));
    }

    function it_should_send_an_inform_request($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new InformRequest(OidValues::timeticks(1), OidValues::oid('1.2.3'), new OidList(new Oid('1.2.3'))), Argument::any())
            ->shouldBeCalled()->willReturn($this->response);

        $this->sendInform(1, '1.2.3', new Oid('1.2.3'))->shouldBeAnInstanceOf(MessageResponseV3::class);
    }

    function it_should_send_a_trap_v1_request($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new TrapV1Request('1.2.3', OidValues::ipAddress('192.168.1.1'), 1, 1, OidValues::timeticks(1), new OidList(new Oid('1.2.3'))), Argument::any())
            ->shouldBeCalled()->willReturn(null);

        $this->sendTrapV1('1.2.3', '192.168.1.1', 1, 1, 1, new Oid('1.2.3'))->shouldBeAnInstanceOf(SnmpClient::class);
    }

    function it_should_send_a_trap_v2_request($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new TrapV2Request(OidValues::timeticks(1), OidValues::oid('1.2.3'), new OidList(new Oid('1.2.3'))), Argument::any())
            ->shouldBeCalled()->willReturn(null);

        $this->sendTrap(1, '1.2.3', new Oid('1.2.3'))->shouldBeAnInstanceOf(SnmpClient::class);
    }

    function it_should_send_a_request_and_get_a_response($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new GetRequest(new OidList(new Oid('1.2.3'))), Argument::any())->shouldBeCalled();

        $this->send(new GetRequest(new OidList(new Oid('1.2.3'))))->shouldBeAnInstanceOf(MessageResponseInterface::class);
    }

    function it_should_get_the_options()
    {
        $this->beConstructedWith([]);
        $this->getOptions()->shouldBeEqualTo([
            'transport' => "udp",
            'use_tls' => false,
            'ssl_validate_cert' => true,
            'ssl_allow_self_signed' => null,
            'ssl_ca_cert' => null,
            'ssl_peer_name' => null,
            'port' => 161,
            'host' => "localhost",
            'user' => null,
            'community' => "public",
            'udp_retry' => 5,
            'timeout_connect' => 5,
            'timeout_read' => 10,
            'version' => 2,
            'security_model' => "usm",
            'engine_id' => null,
            'context_name' => null,
            'use_auth' => false,
            'use_priv' => false,
            'auth_mech' => null,
            'priv_mech' => null,
            'priv_pwd' => null,
            'auth_pwd' => null,
        ]);
    }

    function it_should_get_a_single_oid_if_specified($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new GetRequest(new OidList(new Oid('1.2.3'))), Argument::any())
            ->shouldBeCalled()->willReturn($this->response);

        $this->getOid('1.2.3')->shouldBeLike(Oid::fromCounter('1.2.3', 1));
    }

    function it_should_get_a_single_oid_value_as_a_string_if_specified($handler)
    {
        /** @var ClientProtocolHandler $handler */
        $handler->handle(new GetRequest(new OidList(new Oid('1.2.3'))), Argument::any())
            ->shouldBeCalled()->willReturn($this->response);

        $this->getValue('1.2.3')->shouldBeEqualTo('1');
    }

    function it_should_get_an_SnmpWalk_helper_when_calling_walk()
    {
        $this->walk()->shouldReturnAnInstanceOf(SnmpWalk::class);
    }

    function it_should_get_an_SnmpWalk_helper_with_a_specific_start_and_end_oid_when_calling_walk()
    {
        $this->walk('1.2.3', '1.2.4')->shouldReturnAnInstanceOf(SnmpWalk::class);
    }
}
