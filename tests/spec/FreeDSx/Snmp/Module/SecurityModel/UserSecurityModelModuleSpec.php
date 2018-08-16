<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Module\SecurityModel;

use FreeDSx\Snmp\Exception\RediscoveryNeededException;
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModuleInterface;
use FreeDSx\Snmp\Module\Privacy\PrivacyModuleInterface;
use FreeDSx\Snmp\Module\SecurityModel\TimeSync;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\Protocol\Factory\AuthenticationModuleFactory;
use FreeDSx\Snmp\Protocol\Factory\PrivacyModuleFactory;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\SecurityModel\SecurityModelModuleInterface;
use FreeDSx\Snmp\Module\SecurityModel\UserSecurityModelModule;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Response\ReportResponse;
use FreeDSx\Snmp\Response\Response;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class UserSecurityModelModuleSpec extends ObjectBehavior
{
    protected $options;

    /**
     * @var AbstractMessageV3
     */
    protected $request;

    /**
     * @var AbstractMessageV3
     */
    protected $response;

    function let(AuthenticationModuleFactory $authFactory, PrivacyModuleFactory $privacyFactory, AuthenticationModuleInterface $authModule, PrivacyModuleInterface $privacyModule)
    {
        $this->options = [
            'host' => 'foo',
            'priv_pwd' => 'foobar123',
            'auth_mech' => 'sha1',
            'priv_mech' => 'aes128',
            'use_auth' => true,
            'user' => 'foo',
            'context_engine_id' => null,
            'auth_pwd' => 'foobar123',
        ];

        $privacyFactory->get(Argument::any())->willReturn($privacyModule);
        $authFactory->get(Argument::any())->willReturn($authModule);
        $this->request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList())),
            hex2bin('67889ff865a14762d876cb5ddb640ff582681461bec6'),
            new UsmSecurityParameters('foo', 1, 1, 'foo', 'foobar123', hex2bin('0000000000000384'))

        );
        $this->response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            null,
            hex2bin('67889ff865a14762d874cb5ddb640ff5ca02febb5e2f'),
            new UsmSecurityParameters('foo', 1, 1, 'foo', 'foobar123', hex2bin('0000000000000384'))
        );
        $authModule->authenticateOutgoingMsg(Argument::any(), Argument::any())->willReturn($this->request);
        $authModule->authenticateIncomingMsg(Argument::any(), Argument::any())->willReturn($this->request);

        $this->beConstructedWith($privacyFactory, $authFactory, ['foo' => new TimeSync(1, 2)], ['foo' => 'foo']);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(UserSecurityModelModule::class);
    }

    function it_should_implement_the_security_model_module_interface()
    {
        $this->shouldImplement(SecurityModelModuleInterface::class);
    }

    function it_should_support_the_user_security_model()
    {
        $this->supports()->shouldBeEqualTo(3);
    }

    function it_should_decrypt_an_incoming_message_request_if_it_has_privacy($privacyModule, $authModule)
    {
        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->decryptData($this->request, $authModule, 'foobar123')->shouldBeCalled()->willReturn(
            hex2bin('30140403666f6f0400a00b0201000201000201003000')
        );

        $this->handleIncomingMessage($this->request, $this->options)->getScopedPdu()->shouldBeLike(
            new ScopedPduRequest(new GetRequest(new OidList()), 'foo')
        );
    }

    function it_should_decrypt_an_incoming_message_response_if_it_has_privacy($privacyModule, $authModule)
    {
        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->decryptData(Argument::any(), $authModule, 'foobar123')->shouldBeCalled()->willReturn(
            hex2bin('30140403666f6f0400a20b0201000201000201003000')
        );

        $this->handleIncomingMessage($this->response, $this->options)->getScopedPdu()->shouldBeLike(
            new ScopedPduResponse(new Response(0, 0, 0, new OidList()), 'foo')
        );
    }

    function it_should_not_attempt_to_decrypt_an_incoming_message_if_it_doesnt_have_privacy()
    {
        $this->handleIncomingMessage(new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new Response(0, 0, 0, new OidList())),
            null,
            new UsmSecurityParameters('foo', 1, 1, 'foo', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options)->getScopedPdu()->shouldBeLike(new ScopedPduResponse(new Response(0, 0, 0, new OidList())));
    }

    function it_should_encrypt_an_outgoing_message_if_it_has_privacy($privacyModule, $authModule)
    {
        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->encryptData($this->request, $authModule, 'foobar123')->shouldBeCalled()->willReturn($this->request);
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateOutgoingMsg($this->request, 'foobar123')->shouldBeCalled()->willReturn($this->request);

        $this->handleOutgoingMessage($this->request, $this->options);
    }

    function it_should_authenticate_an_outgoing_message_if_it_has_authentication($authModule)
    {
        $this->request->getMessageHeader()->setFlags(MessageHeader::FLAG_AUTH);
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateOutgoingMsg($this->request, 'foobar123')->shouldBeCalled();
        $this->handleOutgoingMessage($this->request, $this->options);
    }

    function it_should_not_encrypt_an_outgoing_message_if_it_doesnt_have_privacy($privacyModule)
    {
        $this->request->getMessageHeader()->setFlags(MessageHeader::FLAG_AUTH);
        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->encryptData(Argument::any(), Argument::any(),Argument::any())->shouldNotBeCalled();
        $this->handleOutgoingMessage($this->request, $this->options);
    }

    function it_should_not_authenticate_an_outgoing_message_if_it_doesnt_have_authentication($authModule)
    {
        $this->request->getMessageHeader()->setFlags(MessageHeader::FLAG_NO_AUTH_NO_PRIV);
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateOutgoingMsg(Argument::any(), Argument::any())->shouldNotBeCalled();
        $this->handleOutgoingMessage($this->request, $this->options)->getSecurityParameters()->getUsername()->shouldBeEqualTo('foo');
    }

    function it_should_not_require_discovery_when_the_engine_and_time_is_known_and_valid()
    {
        $this->isDiscoveryNeeded($this->request, $this->options)->shouldBeEqualTo(false);
    }

    function it_should_need_a_discovery_if_the_host_is_not_known($authFactory, $privacyFactory)
    {
        $this->beConstructedWith($privacyFactory, $authFactory, [], []);

        $this->isDiscoveryNeeded($this->request, $this->options)->shouldBeEqualTo(true);
    }

    function it_should_need_a_discovery_if_the_engine_time_was_not_cached($authFactory, $privacyFactory)
    {
        $this->beConstructedWith($privacyFactory, $authFactory, [], ['foo' => 'foo']);

        $this->isDiscoveryNeeded($this->request, $this->options)->shouldBeEqualTo(true);
    }

    function it_should_need_discovery_if_the_last_sync_time_was_over_150_seconds($privacyFactory, $authFactory)
    {
        $this->beConstructedWith($privacyFactory, $authFactory, ['foo' => new TimeSync(10, 10, new \DateTime('01-01-2018 16:00:00'))], ['foo' => 'foo']);

        $this->isDiscoveryNeeded($this->request, $this->options)->shouldBeEqualTo(true);
    }

    function it_should_need_throw_a_rediscovery_exception_if_an_incoming_message_has_a_notInTimeWindow_report_response()
    {
        $this->shouldThrow(RediscoveryNeededException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.2.0', 1)))),
            null,
            new UsmSecurityParameters('foo', 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_need_throw_a_SnmpRequestException_if_an_incoming_message_has_a_usmStatsUnsupportedSecLevels_report_response()
    {
        $this->shouldThrow(SnmpRequestException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.1.0', 1)))),
            null,
            new UsmSecurityParameters('foo', 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_need_throw_a_SnmpRequestException_if_an_incoming_message_has_a_usmStatsUnknownUserNames_report_response()
    {
        $this->shouldThrow(SnmpRequestException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.3.0', 1)))),
            null,
            new UsmSecurityParameters('foo', 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_need_throw_a_SnmpRequestException_if_an_incoming_message_has_a_usmStatsWrongDigests_report_response()
    {
        $this->shouldThrow(SnmpRequestException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.5.0', 1)))),
            null,
            new UsmSecurityParameters('foo', 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_need_throw_a_SnmpRequestException_if_an_incoming_message_has_a_usmStatsDecryptionErrors_report_response()
    {
        $this->shouldThrow(SnmpRequestException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.6.0', 1)))),
            null,
            new UsmSecurityParameters('foo', 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_throw_an_SnmpRequestException_if_the_expected_engine_id_does_not_match_the_actual_engine_id()
    {
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList())),
            null,
            new UsmSecurityParameters('bar', 1, 300, '', '', hex2bin(''))
        );
        $this->shouldThrow(new SnmpRequestException($response, 'The expected engine ID does not match the known engine ID for this host.'))->during('handleIncomingMessage', [$response, $this->options]);
    }

    function it_should_get_a_discovery_request()
    {
        $this->getDiscoveryRequest($this->request, $this->options)->shouldBeAnInstanceOf(MessageRequestV3::class);
        $this->getDiscoveryRequest($this->request, $this->options)->getScopedPdu()->shouldBeLike(new ScopedPduRequest(new GetRequest(new OidList()), ''));
        $this->getDiscoveryRequest($this->request, $this->options)->getSecurityParameters()->shouldBeLike(new UsmSecurityParameters('', 0, 0));
    }

    function it_should_handle_a_discovery_response($privacyModule, $authModule)
    {
        $this->request->setScopedPdu(new ScopedPduRequest(new GetRequest(new OidList())));
        $response = new MessageResponseV3(
            new MessageHeader(0, MessageHeader::FLAG_REPORTABLE, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.4.0', 1))), 'foobar'),
            null,
            new UsmSecurityParameters('foobar', 15, 20, 'foo')
        );
        $privacyModule->encryptData($this->request, $authModule, 'foobar123')->willReturn($this->request);

        $this->handleDiscoveryResponse($this->request, $response, $this->options);
        $this->handleOutgoingMessage($this->request, $this->options)->getSecurityParameters()->shouldBeLike(
            new UsmSecurityParameters('foobar', 15, 20, 'foo')
        );
    }

    function it_should_throw_an_exception_if_the_discovery_response_has_no_engine_id()
    {
        $this->request->setScopedPdu(new ScopedPduRequest(new GetRequest(new OidList())));
        $response = new MessageResponseV3(
            new MessageHeader(0, MessageHeader::FLAG_REPORTABLE, 3),
            new ScopedPduResponse(new ReportResponse(1), ''),
            null,
            new UsmSecurityParameters('', 15, 20, 'foo')
        );

        $this->shouldThrow(SnmpRequestException::class)->during('handleDiscoveryResponse', [$this->request, $response, $this->options]);
    }

    function it_should_throw_an_exception_if_the_discovery_response_is_not_a_report_response()
    {
        $this->request->setScopedPdu(new ScopedPduRequest(new GetRequest(new OidList())));
        $response = new MessageResponseV3(
            new MessageHeader(0, MessageHeader::FLAG_REPORTABLE, 3),
            new ScopedPduResponse(new Response(1), 'foobar'),
            null,
            new UsmSecurityParameters('foobar', 15, 20, 'foo')
        );

        $this->shouldThrow(SnmpRequestException::class)->during('handleDiscoveryResponse', [$this->request, $response, $this->options]);
    }
}
