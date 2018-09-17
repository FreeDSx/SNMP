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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\SecurityModel\SecurityModelModuleInterface;
use FreeDSx\Snmp\Module\SecurityModel\Usm\UsmUser;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Protocol\Factory\SecurityModelModuleFactory;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Protocol\TrapProtocolHandler;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Trap\TrapListenerInterface;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class TrapProtocolHandlerSpec extends ObjectBehavior
{
    /**
     * @var array
     */
    protected $options = [
        'blacklist' => null,
        'whitelist' => null,
        'version' => null,
    ];

    protected $v2TrapAsn1;

    protected $v2InformAsn1;

    protected $encodedTrapV2;

    protected $v3MessageWithTrap;

    function let(TrapListenerInterface $trapListener, SnmpEncoder $encoder, Socket $socket, SecurityModelModuleFactory $securityModelFactory, SecurityModelModuleInterface $securityModule)
    {
        $securityModelFactory->get(Argument::any())->willReturn($securityModule);

        $snmpEncoder = new SnmpEncoder();
        $pdu = '';
        foreach ((new TrapV2Request(OidValues::timeticks(123), OidValues::oid('1.2.3'), new OidList()))->toAsn1() as $child) {
            $pdu .= $snmpEncoder->encode($child);
        }
        $this->encodedTrapV2 = Asn1::context(7, new IncompleteType($pdu))->setIsConstructed(true);

        $this->v2TrapAsn1 = Asn1::sequence(
            Asn1::integer(1),
            Asn1::octetString('foo'),
            $this->encodedTrapV2
        );
        $this->v2InformAsn1 = Asn1::sequence(
            Asn1::integer(1),
            Asn1::octetString('foo'),
            Asn1::context(6, new IncompleteType($pdu))->setIsConstructed(true)
        );
        $this->v3MessageWithTrap = new MessageRequestV3(
            new MessageHeader(1),
            new ScopedPduRequest(
                new TrapV2Request(OidValues::timeticks(123), OidValues::oid('1.2.3')),
                EngineId::fromText('foobar')
            ),
            null,
            new UsmSecurityParameters(EngineId::fromText('foobar'), 0, 0, 'user1')
        );
        $this->beConstructedWith($trapListener, $this->options, $encoder, $socket, $securityModelFactory);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(TrapProtocolHandler::class);
    }

    function it_should_not_handle_a_trap_if_the_listener_rejects_the_source_ip($trapListener)
    {
        $trapListener->accept('127.0.0.1')->willReturn(false);
        $trapListener->receive(Argument::any())->shouldNotBeCalled();

        $this->handle('127.0.0.1:12345', 'foo', []);
    }

    function it_should_skip_a_message_if_it_cannot_be_decoded($trapListener, $encoder)
    {
        $trapListener->accept('127.0.0.1')->willReturn(true);
        $trapListener->receive(Argument::any())->shouldNotBeCalled();
        $encoder->decode(Argument::any())->willThrow(EncoderException::class);

        $this->handle('127.0.0.1:12345', 'foobar', []);
    }

    function it_should_skip_a_message_if_a_whitelist_is_defined_an_the_ip_is_not_in_it($trapListener)
    {
        $trapListener->accept(Argument::any())->shouldNotBeCalled();
        $trapListener->receive(Argument::any())->shouldNotBeCalled();

        $this->handle('127.0.0.1:12345', 'foobar', ['whitelist' => ['192.168.1.1']]);
    }

    function it_should_allow_a_message_if_the_trap_is_sent_from_an_ip_in_the_whitelist($trapListener, $encoder)
    {
        $trapListener->accept(Argument::any())->shouldNotBeCalled();
        $trapListener->receive(Argument::any())->shouldBeCalled();
        $encoder->decode(Argument::any())->willReturn($this->v2TrapAsn1);

        $this->handle('127.0.0.1:12345', 'foobar', ['whitelist' => ['127.0.0.1']]);
    }

    function it_should_skip_the_message_if_the_version_is_not_allowed($trapListener, $encoder)
    {
        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldNotBeCalled();
        $encoder->decode(Argument::any())->willReturn($this->v2TrapAsn1);

        $this->handle('127.0.0.1:12345', 'foobar', ['version' => 3]);
    }

    function it_should_allow_the_message_if_the_version_is_allowed($trapListener, $encoder)
    {
        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldBeCalled();
        $encoder->decode(Argument::any())->willReturn($this->v2TrapAsn1);

        $this->handle('127.0.0.1:12345', 'foobar', ['version' => 2]);
    }

    function it_should_skip_the_message_if_only_a_specific_community_is_defined_and_it_does_not_match($trapListener, $encoder)
    {
        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldNotBeCalled();
        $encoder->decode(Argument::any())->willReturn($this->v2TrapAsn1);

        $this->handle('127.0.0.1:12345', 'foobar', ['community' => 'bar']);
    }

    function it_should_allow_the_message_if_only_a_specific_community_is_defined_and_it_does_match($trapListener, $encoder)
    {
        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldBeCalled();
        $encoder->decode(Argument::any())->willReturn($this->v2TrapAsn1);

        $this->handle('127.0.0.1:12345', 'foobar', ['community' => 'foo']);
    }

    function it_should_send_a_response_for_inform_requests($trapListener, $encoder, $socket)
    {
        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldBeCalled();
        $encoder->decode(Argument::any())->willReturn($this->v2InformAsn1);
        $encoder->encode(Argument::any())->willReturn('foo');

        $socket->write(Argument::any())->shouldBeCalled();
        $this->handle('127.0.0.1:12345', 'foobar', []);
    }

    function it_should_send_a_v1_trap_to_the_listener($trapListener, $encoder)
    {
        $pdu = Asn1::sequence(
            Asn1::oid('1.2.3'),
            OidValues::ipAddress('192.168.1.1')->toAsn1(),
            Asn1::integer(1),
            Asn1::integer(2),
            OidValues::timeticks(1)->toAsn1(),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    OidValues::counter(1)->toAsn1()
                )
            )
        );

        $snmpEncoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $snmpEncoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $v1TrapAsn1 = Asn1::sequence(
            Asn1::integer(0),
            Asn1::octetString('foo'),
            Asn1::context(4, $pdu)->setIsConstructed(true)
        );

        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldBeCalled();
        $encoder->decode(Argument::any())->willReturn($v1TrapAsn1);

        $this->handle('192.168.1.1:12345', 'foo', []);
    }

    function it_should_send_a_v3_trap_to_the_listener($trapListener, $encoder, $securityModule)
    {
        $trapV3 = Asn1::sequence(
            Asn1::integer(3),
            (new MessageHeader(0, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3))->toAsn1(),
            Asn1::octetString((new SnmpEncoder())->encode((new UsmSecurityParameters(EngineId::fromText('foobar'), 0, 0, 'user1'))->toAsn1())),
            Asn1::sequence(
                Asn1::octetString(EngineId::fromText('foobar')->toBinary()),
                Asn1::octetString(''),
                $this->encodedTrapV2
            )
        );

        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldBeCalled();
        $encoder->decode(Argument::any())->willReturn($trapV3);
        $trapListener->getUsmUser(Argument::any(), '192.168.1.1', 'user1')->shouldBeCalled()->willReturn(new UsmUser('user1'));

        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->willReturn($this->v3MessageWithTrap);

        $this->handle('192.168.1.1:12345', 'foo', []);
    }

    function it_should_handle_a_v3_message_thats_encrypted($trapListener, $encoder, $securityModule)
    {
        $trapV3 = Asn1::sequence(
            Asn1::integer(3),
            (new MessageHeader(0, MessageHeader::FLAG_AUTH_PRIV, 3))->toAsn1(),
            Asn1::octetString((new SnmpEncoder())->encode((new UsmSecurityParameters(EngineId::fromText('foobar123'), 0, 0, 'user1'))->toAsn1())),
            Asn1::octetString('foobar123')
        );

        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldBeCalled();
        $encoder->decode(Argument::any())->willReturn($trapV3);
        $trapListener->getUsmUser(Argument::any(), '192.168.1.1', 'user1')->shouldBeCalled()->willReturn(new UsmUser('user1'));

        $securityModule->handleIncomingMessage(Argument::any(), Argument::any())->willReturn($this->v3MessageWithTrap);

        $this->handle('192.168.1.1:12345', 'foo', []);
    }

    function it_should_not_send_a_trap_to_the_listener_when_a_usm_user_is_not_found_for_v3($trapListener, $encoder)
    {
        $trapV3 = Asn1::sequence(
            Asn1::integer(3),
            (new MessageHeader(0, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3))->toAsn1(),
            Asn1::octetString((new SnmpEncoder())->encode((new UsmSecurityParameters(EngineId::fromText('foobar'), 0, 0, 'user1'))->toAsn1())),
            Asn1::sequence(
                Asn1::octetString(EngineId::fromText('foobar')->toBinary()),
                Asn1::octetString(''),
                $this->encodedTrapV2
            )
        );

        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldNotBeCalled();
        $encoder->decode(Argument::any())->willReturn($trapV3);
        $trapListener->getUsmUser(Argument::any(), Argument::any(), Argument::any())->willReturn(null);

        $this->handle('192.168.1.1:12345', 'foo', []);
    }

    function it_should_handle_a_v3_and_pass_all_user_options_to_the_security_module($trapListener, $encoder, $securityModule)
    {
        $trapV3 = Asn1::sequence(
            Asn1::integer(3),
            (new MessageHeader(0, MessageHeader::FLAG_AUTH_PRIV, 3))->toAsn1(),
            Asn1::octetString((new SnmpEncoder())->encode((new UsmSecurityParameters(EngineId::fromText('foobar'), 0, 0, 'user1'))->toAsn1())),
            Asn1::sequence(
                Asn1::octetString(EngineId::fromText('foobar')->toBinary()),
                Asn1::octetString(''),
                $this->encodedTrapV2
            )
        );
        $trapListener->accept(Argument::any())->willReturn(true);
        $trapListener->receive(Argument::any())->shouldBeCalled();
        $encoder->decode(Argument::any())->willReturn($trapV3);
        $trapListener->getUsmUser(Argument::any(), '192.168.1.1', 'user1')->shouldBeCalled()->willReturn(
            UsmUser::withPrivacy('user1', 'user1password', 'sha512', 'user1privacy', 'aes128')
        );

        $options = ["timeout_connect" => 5, "timeout_read" => 10, "ssl_validate_cert" => true, "ssl_allow_self_signed" => null, "ssl_ca_cert" => null, "ssl_peer_name" => null, "whitelist" => null, "version" => null, "community" => null, "engine_id" => null, "blacklist" => null, "user" => "user1", "use_auth" => true, "use_priv" => true, "auth_mech" => "sha512", "auth_pwd" => "user1password", "priv_mech" => "aes128", "priv_pwd" => "user1privacy"];
        $securityModule->handleIncomingMessage(Argument::any(), $options)->willReturn($this->v3MessageWithTrap);

        $this->handle('192.168.1.1:12345', 'foo', []);
    }

    function it_should_only_accept_traps_and_inform_requests($trapListener, $encoder)
    {
        $pdu = Asn1::sequence(
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    Asn1::null()
                )
            )
        );

        $snmpEncoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $snmpEncoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $getRequest = Asn1::sequence(
            Asn1::integer(1),
            Asn1::octetString('foo'),
            Asn1::context(0, $pdu)->setIsConstructed(true)
        );

        $trapListener->accept(Argument::any())->willReturn(true);
        $encoder->decode(Argument::any())->willReturn($getRequest);

        $trapListener->receive(Argument::any())->shouldNotBeCalled();
    }

    function it_should_not_accept_requests_that_dont_match_the_SNMP_version($trapListener, $encoder)
    {
        $inform = $this->v2InformAsn1;
        $inform->getChild(0)->setValue(0);
        $trapListener->accept(Argument::any())->willReturn(true);
        $encoder->decode(Argument::any())->willReturn($inform);

        $trapListener->receive(Argument::any())->shouldNotBeCalled();
        $this->handle('127.0.0.1:12345', 'foobar', []);
    }
}
