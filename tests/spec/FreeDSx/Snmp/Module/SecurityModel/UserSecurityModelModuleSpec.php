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
use FreeDSx\Snmp\Exception\SecurityModelException;
use FreeDSx\Snmp\Exception\SnmpAuthenticationException;
use FreeDSx\Snmp\Exception\SnmpEncryptionException;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModuleInterface;
use FreeDSx\Snmp\Module\Privacy\PrivacyModuleInterface;
use FreeDSx\Snmp\Module\SecurityModel\Usm\TimeSync;
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
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Response\ReportResponse;
use FreeDSx\Snmp\Response\Response;
use FreeDSx\Snmp\Value\OidValue;
use FreeDSx\Snmp\Value\TimeTicksValue;
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
            'use_priv' => true,
            'user' => 'foo',
            'engine_id' => null,
            'auth_pwd' => 'foobar123',
        ];

        $privacyFactory->get(Argument::any())->willReturn($privacyModule);
        $authFactory->get(Argument::any())->willReturn($authModule);
        $this->request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            hex2bin('67889ff865a14762d876cb5ddb640ff582681461bec6'),
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 300, 'foo', 'foobar123', hex2bin('0000000000000384'))

        );
        $this->response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduResponse(new Response(0), EngineId::fromText('foo')),
            hex2bin('67889ff865a14762d874cb5ddb640ff5ca02febb5e2f'),
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 300, 'foo', 'foobar123', hex2bin('0000000000000384'))
        );
        $authModule->authenticateOutgoingMsg(Argument::any(), Argument::any())->willReturn($this->request);
        $authModule->authenticateIncomingMsg(Argument::any(), Argument::any())->willReturn($this->request);

        $this->beConstructedWith($privacyFactory, $authFactory, [EngineId::fromText('foo')->toBinary() => new TimeSync(1, 300)], ['foo' => EngineId::fromText('foo')]);
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

    function it_should_authenticate_an_incoming_message_request_if_authentication_is_specified($authModule, $privacyModule)
    {
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateIncomingMsg(Argument::any(), 'foobar123')->shouldBeCalled()->willReturn($this->request);
        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->decryptData(Argument::any(), Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->handleIncomingMessage($this->request, array_merge($this->options, ['use_priv' => false,]))->shouldBeEqualTo($this->request);
    }

    function it_should_decrypt_an_incoming_message_request_if_it_has_privacy($privacyModule, $authModule)
    {
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateIncomingMsg(Argument::any(), 'foobar123')->shouldBeCalled()->willReturn($this->request);
        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->decryptData(Argument::any(), $authModule, 'foobar123')->shouldBeCalled()->willReturn($this->request);

        $this->handleIncomingMessage($this->request, $this->options)->getScopedPdu()->shouldBeLike(
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo'))
        );
    }

    function it_should_decrypt_an_incoming_message_response_if_it_has_privacy($privacyModule, $authModule)
    {
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateIncomingMsg(Argument::any(), 'foobar123')->shouldBeCalled()->willReturn($this->response);
        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->decryptData(Argument::any(), $authModule, 'foobar123')->shouldBeCalled()->willReturn($this->response);

        $this->handleIncomingMessage($this->response, $this->options)->getScopedPdu()->shouldBeLike(
            new ScopedPduResponse(new Response(0, 0, 0, new OidList()), EngineId::fromText('foo'))
        );
    }

    function it_should_not_attempt_to_decrypt_an_incoming_message_if_it_doesnt_have_privacy()
    {
        $this->handleIncomingMessage(new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new Response(0, 0, 0, new OidList())),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 300, 'foo', 'foobar123', hex2bin('0000000000000384'))
        ), array_merge($this->options, ['use_auth' => false, 'use_priv' => false,]))->getScopedPdu()->shouldBeLike(new ScopedPduResponse(new Response(0, 0, 0, new OidList())));
    }

    function it_should_encrypt_an_outgoing_message_response_if_it_has_privacy($privacyModule, $authModule)
    {
        $response1 = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduResponse(new Response(0)),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );
        $response2 = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            null,
            hex2bin('5649df94a907aa48bfe6e074c5b3cbc7f2840a219bd175e0d33a4163f8a8d1637dba55a2665fc356'),
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123', hex2bin('fe609d2981ff5a0f'))
        );

        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->encryptData($response1, $authModule, 'foobar123')->shouldBeCalled()->willReturn($response2);
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateOutgoingMsg($response2, 'foobar123')->shouldBeCalled()->willReturn($response2);

        $this->handleOutgoingMessage($response1, $this->options);
    }

    function it_should_encrypt_an_outgoing_message_request_if_it_has_privacy($privacyModule, $authModule)
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

    function it_should_set_the_engine_boots_and_time_correctly_for_a_trap()
    {
        $this->request->getMessageHeader()->setFlags(MessageHeader::FLAG_NO_AUTH_NO_PRIV);
        $this->request->getScopedPdu()->setRequest(new TrapV2Request(new TimeTicksValue(1), new OidValue('1.2.3')));

        $engineId = EngineId::fromText('foobar123');
        $this->handleOutgoingMessage($this->request, array_merge($this->options, ['engine_id' => $engineId]))->getSecurityParameters()->shouldBeLike(new UsmSecurityParameters(
            $engineId, 0, 0, 'foo'
        ));
    }

    function it_should_generate_an_engine_id_for_a_trap_if_needed_on_an_outgoing_message()
    {
        $this->request->getMessageHeader()->setFlags(MessageHeader::FLAG_NO_AUTH_NO_PRIV);
        $this->request->getScopedPdu()->setRequest(new TrapV2Request(new TimeTicksValue(1), new OidValue('1.2.3')));

        $this->handleOutgoingMessage($this->request, $this->options)->getSecurityParameters()->getEngineId()->getFormat()->shouldBeEqualTo(EngineId::FORMAT_IPV4);
    }

    function it_should_not_generate_an_engine_id_for_an_inform_request_on_an_outgoing_message()
    {
        $this->request->getMessageHeader()->setFlags(MessageHeader::FLAG_NO_AUTH_NO_PRIV);
        $this->request->getScopedPdu()->setRequest(new InformRequest(new TimeTicksValue(1), new OidValue('1.2.3')));

        # Need to call toBinary due to an optimization...
        $engineId = EngineId::fromText('foo');
        $engineId->toBinary();

        $this->handleOutgoingMessage($this->request, $this->options)->getSecurityParameters()->getEngineId()->shouldBeLike($engineId);
    }

    function it_should_use_the_defined_engine_id_for_a_trap_on_an_outgoing_message()
    {
        $this->request->getMessageHeader()->setFlags(MessageHeader::FLAG_NO_AUTH_NO_PRIV);
        $this->request->getScopedPdu()->setRequest(new TrapV2Request(new TimeTicksValue(1), new OidValue('1.2.3')));

        $engineId = EngineId::fromText('foobar123');
        $this->handleOutgoingMessage($this->request, array_merge($this->options, ['engine_id' => $engineId]))->getSecurityParameters()->getEngineId()->shouldBeEqualTo($engineId);
    }

    function it_should_not_require_discovery_when_the_engine_and_time_is_known_and_valid()
    {
        $this->isDiscoveryRequestNeeded($this->request, $this->options)->shouldBeEqualTo(false);
    }

    function it_should_not_require_discovery_when_the_outgoing_request_is_a_trap()
    {
        $this->request->getScopedPdu()->setRequest(new TrapV2Request(new TimeTicksValue(1), new OidValue('1.2.3')));

        $this->isDiscoveryRequestNeeded($this->request, $this->options)->shouldBeEqualTo(false);
    }

    function it_should_require_discovery_when_the_outgoing_request_is_an_inform($authFactory, $privacyFactory)
    {
        $this->beConstructedWith($privacyFactory, $authFactory, [], []);
        $this->request->getScopedPdu()->setRequest(new InformRequest(new TimeTicksValue(1), new OidValue('1.2.3')));

        $this->isDiscoveryRequestNeeded($this->request, $this->options)->shouldBeEqualTo(true);
    }

    function it_should_need_a_discovery_if_the_host_is_not_known($authFactory, $privacyFactory)
    {
        $this->beConstructedWith($privacyFactory, $authFactory, [], []);

        $this->isDiscoveryRequestNeeded($this->request, $this->options)->shouldBeEqualTo(true);
    }

    function it_should_need_a_discovery_if_the_engine_time_was_not_cached($authFactory, $privacyFactory)
    {
        $this->beConstructedWith($privacyFactory, $authFactory, [], ['foo' => 'foo']);

        $this->isDiscoveryRequestNeeded($this->request, $this->options)->shouldBeEqualTo(true);
    }

    function it_should_need_discovery_if_the_last_sync_time_was_over_150_seconds($privacyFactory, $authFactory)
    {
        $this->beConstructedWith($privacyFactory, $authFactory, [EngineId::fromText('foo')->toBinary() => new TimeSync(10, 10, new \DateTime('01-01-2018 16:00:00'))], ['foo' => EngineId::fromText('foo')]);

        $this->isDiscoveryRequestNeeded($this->request, $this->options)->shouldBeEqualTo(true);
    }

    function it_should_throw_a_rediscovery_exception_if_an_incoming_message_has_a_notInTimeWindow_report_response()
    {
        $this->shouldThrow(RediscoveryNeededException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.2.0', 1)))),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), array_merge($this->options, ['use_auth' => false, 'use_priv' => false,])]);
    }

    function it_should_need_throw_a_SecurityModelException_if_an_incoming_message_has_a_usmStatsUnsupportedSecLevels_report_response()
    {
        $this->shouldThrow(SecurityModelException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.1.0', 1)))),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_need_throw_a_SecurityModelException_if_an_incoming_message_has_a_usmStatsUnknownUserNames_report_response()
    {
        $this->shouldThrow(SecurityModelException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.3.0', 1)))),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_need_throw_a_SecurityModelException_if_an_incoming_message_has_a_usmStatsWrongDigests_report_response()
    {
        $this->shouldThrow(SecurityModelException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.5.0', 1)))),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_need_throw_a_SecurityModelException_if_an_incoming_message_has_a_usmStatsDecryptionErrors_report_response()
    {
        $this->shouldThrow(SecurityModelException::class)->during('handleIncomingMessage', [new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.6.0', 1)))),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 300, '', 'foobar123', hex2bin('0000000000000384'))
        ), $this->options]);
    }

    function it_should_throw_an_SecurityModelException_if_the_expected_engine_id_does_not_match_the_actual_engine_id()
    {
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new Response(1, 0, 0, new OidList())),
            null,
            new UsmSecurityParameters(EngineId::fromText('bar'), 1, 300, '', '', '')
        );
        $this->shouldThrow(new SecurityModelException('The expected engine ID does not match the known engine ID for this host.'))->during(
            'handleIncomingMessage',
            [$response, array_merge($this->options, ['use_auth' => false, 'use_priv' => false,])]
        );
    }

    function it_should_throw_a_SecurityModelException_if_an_incoming_message_is_not_in_the_time_window()
    {
        $response1 = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new Response(1, 0, 0, new OidList())),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 149, '', '', '')
        );
        $this->shouldThrow(new SecurityModelException('The received message is outside of the time window.'))->during(
            'handleIncomingMessage',
            [$response1, array_merge($this->options, ['use_auth' => false, 'use_priv' => false,])]
        );

        $response2 = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new Response(1, 0, 0, new OidList())),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 0, 300, '', '', '')
        );
        $this->shouldThrow(new SecurityModelException('The received message is outside of the time window.'))->during(
            'handleIncomingMessage',
            [$response2, array_merge($this->options, ['use_auth' => false, 'use_priv' => false,])]
        );
    }

    function it_should_update_the_cached_time_on_an_incoming_message_if_needed()
    {
        $engineId = EngineId::fromText('foo');
        $engineId->toBinary();
        $request = $this->request;
        $request->setMessageHeader(new MessageHeader(1));
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
            new ScopedPduResponse(new Response(1, 0, 0, new OidList())),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 2, 100 , '', '', '')
        );
        $this->handleIncomingMessage($response, array_merge($this->options, ['use_auth' => false, 'use_priv' => false,]));
        $this->handleOutgoingMessage($request, array_merge($this->options, ['use_auth' => false, 'use_priv' => false,]))->getSecurityParameters()->shouldBeLike(
            new UsmSecurityParameters($engineId, 2, 100, 'foo')
        );
    }

    function it_should_get_a_discovery_request()
    {
        $this->getDiscoveryRequest($this->request, $this->options)->shouldBeAnInstanceOf(MessageRequestV3::class);
        $this->getDiscoveryRequest($this->request, $this->options)->getScopedPdu()->shouldBeLike(new ScopedPduRequest(new GetRequest(new OidList()), null));
        $this->getDiscoveryRequest($this->request, $this->options)->getSecurityParameters()->shouldBeLike(new UsmSecurityParameters(null, 0, 0));
    }

    function it_should_handle_a_discovery_response($privacyModule, $authModule)
    {
        $this->request->setScopedPdu(new ScopedPduRequest(new GetRequest(new OidList())));
        $response = new MessageResponseV3(
            new MessageHeader(0, MessageHeader::FLAG_REPORTABLE, 3),
            new ScopedPduResponse(new ReportResponse(1, 0, 0, new OidList(Oid::fromCounter('1.3.6.1.6.3.15.1.1.4.0', 1))), EngineId::fromText('foobar')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foobar'), 15, 20, 'foo')
        );
        $privacyModule->encryptData($this->request, $authModule, 'foobar123')->willReturn($this->request);

        # Performs an optimization, needed for comparison...
        $engine = EngineId::fromText('foobar');
        $engine->toBinary();

        $this->handleDiscoveryResponse($this->request, $response, $this->options);
        $this->handleOutgoingMessage($this->request, $this->options)->getSecurityParameters()->shouldBeLike(
            new UsmSecurityParameters($engine, 15, 20, 'foo')
        );
    }

    function it_should_throw_an_exception_if_the_discovery_response_has_no_engine_id()
    {
        $this->request->setScopedPdu(new ScopedPduRequest(new GetRequest(new OidList())));
        $response = new MessageResponseV3(
            new MessageHeader(0, MessageHeader::FLAG_REPORTABLE, 3),
            new ScopedPduResponse(new ReportResponse(1), null),
            null,
            new UsmSecurityParameters(null, 15, 20, 'foo')
        );

        $this->shouldThrow(SecurityModelException::class)->during('handleDiscoveryResponse', [$this->request, $response, $this->options]);
    }

    function it_should_throw_an_exception_if_the_discovery_response_is_not_a_report_response()
    {
        $this->request->setScopedPdu(new ScopedPduRequest(new GetRequest(new OidList())));
        $response = new MessageResponseV3(
            new MessageHeader(0, MessageHeader::FLAG_REPORTABLE, 3),
            new ScopedPduResponse(new Response(1), EngineId::fromText('foobar')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foobar'), 15, 20, 'foo')
        );

        $this->shouldThrow(SecurityModelException::class)->during('handleDiscoveryResponse', [$this->request, $response, $this->options]);
    }

    function it_should_throw_an_SecurityModelException_if_the_incoming_message_fails_to_authenticate($authModule)
    {
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateIncomingMsg(Argument::any(), 'foobar123')->willThrow(new SnmpAuthenticationException('The digest is invalid.'));
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduResponse(new Response(1), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123', hex2bin('0000000000000384'))
        );

        $this->shouldThrow(new SecurityModelException('The digest is invalid.'))->during(
            'handleIncomingMessage',
            [$response, array_merge($this->options, ['use_priv' => false,])]
        );
    }

    function it_should_throw_a_security_model_exception_if_the_encrypted_pdu_cannot_be_decrypted($privacyModule, $authModule)
    {
        /** @var AuthenticationModuleInterface $authModule */
        $authModule->authenticateIncomingMsg(Argument::any(), 'foobar123')->shouldBeCalled()->willReturn($this->request);
        /** @var PrivacyModuleInterface $privacyModule */
        $privacyModule->decryptData(Argument::any(), $authModule, 'foobar123')->shouldBeCalled()->willThrow(new SnmpEncryptionException('Failed to assemble decrypted PDU.'));

        $this->shouldThrow(new SecurityModelException('Failed to assemble decrypted PDU.'))->during('handleIncomingMessage', [$this->request, $this->options]);
    }
}
