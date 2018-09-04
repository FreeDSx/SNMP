<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Module\Authentication;

use FreeDSx\Snmp\Exception\SnmpAuthenticationException;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModule;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModuleInterface;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Request\GetRequest;
use PhpSpec\ObjectBehavior;

class AuthenticationModuleSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('sha1');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(AuthenticationModule::class);
    }

    function it_should_implement_the_AuthenticationModuleInterface()
    {
        $this->shouldImplement(AuthenticationModuleInterface::class);
    }

    function it_should_get_the_supported_authentication_mechanisms()
    {
        $this::supports()->shouldBeEqualTo([
            'md5',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512',
        ]);
    }

    function it_should_hash_a_value_with_md5()
    {
        $this->beConstructedWith('md5');
        $this->hash('foobar123')->shouldBeEqualTo(hex2bin('ae2d699aca20886f6bed96a0425c6168'));
    }

    function it_should_hash_a_value_with_sha1()
    {
        $this->beConstructedWith('sha1');
        $this->hash('foobar123')->shouldBeEqualTo(hex2bin('6FFD8B80F2A76CA670AE33AB196F7936D59FB43B'));
    }

    function it_should_hash_a_value_with_sha224()
    {
        $this->beConstructedWith('sha224');
        $this->hash('foobar123')->shouldBeEqualTo(hex2bin('adc61a6f0296b87c5e30d85cb6913bb795349cbbb9bdbb51046d4076'));
    }

    function it_should_has_a_value_with_sha256()
    {
        $this->beConstructedWith('sha256');
        $this->hash('foobar123')->shouldBeEqualTo(hex2bin('426a1c28c61b7ba258fa3cc300ba7cd3abc11c0d4b585d3ce4a15d6f22d6d363'));
    }

    function it_should_has_a_value_with_sha384()
    {
        $this->beConstructedWith('sha384');
        $this->hash('foobar123')->shouldBeEqualTo(hex2bin('18e0a12833360e8c9dcfab4067d2dbfee9dfd4b16ba6d4807ceef141b89fe934530d04f698bb977e4b919f606f054e49'));
    }

    function it_should_hash_a_value_with_sha512()
    {
        $this->beConstructedWith('sha512');
        $this->hash('foobar123')->shouldBeEqualTo(hex2bin('9430ece67e0222d318ad98a8d74bc7c0edb2041ba38ab72d530c4ede62d9a5be7eb57e193ae8b35c9fa71726950e07537030af8dd6763ae8734d08f189c4d96e'));
    }

    function it_should_throw_an_exception_if_the_hash_fails()
    {
        $this->beConstructedWith('foo');
        $this->shouldThrow(\Throwable::class)->during('hash',['foobar123']);
    }

    /**
     * RFC 3411, A.3.1
     */
    function it_should_generate_a_key_using_md5()
    {
        $this->beConstructedWith('md5');
        $this->generateKey('maplesyrup', EngineId::fromBinary(hex2bin('000000000000000000000002')))->shouldBeEqualTo(
            hex2bin('526f5eed9fcce26f8964c2930787d82b')
        );
    }

    /**
     * RFC 3411, A.3.2
     */
    function it_should_generate_a_key_using_sha1()
    {
        $this->beConstructedWith('sha1');
        $this->generateKey('maplesyrup', EngineId::fromBinary(hex2bin('000000000000000000000002')))->shouldBeEqualTo(
            hex2bin('6695febc9288e36282235fc7151f128497b38f3f')
        );
    }

    function it_should_authenticate_an_outgoing_message_with_md5()
    {
        $this->beConstructedWith('md5');
        $this->authenticateOutgoingMsg(new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo')
        ), 'maplesyrup')->getSecurityParameters()->getAuthParams()->shouldBeEqualTo(hex2bin("63ca6b44dce27a3b41835573"));
    }

    function it_should_authenticate_an_outgoing_message_with_sha1()
    {
        $this->beConstructedWith('sha1');
        $this->authenticateOutgoingMsg(new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo')
        ), 'maplesyrup')->getSecurityParameters()->getAuthParams()->shouldBeEqualTo(hex2bin('05ada614688125b4a9034c6a'));
    }

    function it_should_authenticate_an_outgoing_message_with_sha224()
    {
        $this->beConstructedWith('sha224');
        $this->authenticateOutgoingMsg(new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo')
        ), 'maplesyrup')->getSecurityParameters()->getAuthParams()->shouldBeEqualTo(hex2bin('c60e94ce3cd114c01744de08bf2610a2'));
    }

    function it_should_authenticate_an_outgoing_message_with_sha256()
    {
        $this->beConstructedWith('sha256');
        $this->authenticateOutgoingMsg(new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo')
        ), 'maplesyrup')->getSecurityParameters()->getAuthParams()->shouldBeEqualTo(hex2bin('1abfd2cb6bc2acad91f25572bbee1ca80719da481cc6dd66'));
    }

    function it_should_authenticate_an_outgoing_message_with_sha384()
    {
        $this->beConstructedWith('sha384');
        $this->authenticateOutgoingMsg(new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo')
        ), 'maplesyrup')->getSecurityParameters()->getAuthParams()->shouldBeEqualTo(hex2bin('3bd5d0778d96ecf4179eb98ec3afff423dad2c2ea4dfd8efd2b970bd24b184f4'));
    }

    function it_should_authenticate_an_outgoing_message_with_sha512()
    {
        $this->beConstructedWith('sha512');
        $this->authenticateOutgoingMsg(new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo')
        ), 'maplesyrup')->getSecurityParameters()->getAuthParams()->shouldBeEqualTo(hex2bin('2c1c10a4e405f1b63749c7c6adb5025cd7f0ab9a26a3001c34ca8e5c3e895f1c98a07b12308dcb9d9c389b7395ed098f'));
    }

    function it_should_authenticate_an_incoming_message_with_md5()
    {
        $this->beConstructedWith('md5');
        $message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', hex2bin("63ca6b44dce27a3b41835573"))
        );
        $this->authenticateIncomingMsg($message, 'maplesyrup')->shouldBeEqualTo($message);
    }

    function it_should_authenticate_an_incoming_message_with_sha1()
    {
        $this->beConstructedWith('sha1');
        $message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', hex2bin('05ada614688125b4a9034c6a'))
        );
        $this->authenticateIncomingMsg($message, 'maplesyrup')->shouldBeEqualTo($message);
    }

    function it_should_authenticate_an_incoming_message_with_sha224()
    {
        $this->beConstructedWith('sha224');
        $message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', hex2bin('c60e94ce3cd114c01744de08bf2610a2'))
        );
        $this->authenticateIncomingMsg($message, 'maplesyrup')->shouldBeEqualTo($message);
    }

    function it_should_authenticate_an_incoming_message_with_sha256()
    {
        $this->beConstructedWith('sha256');
        $message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', hex2bin('1abfd2cb6bc2acad91f25572bbee1ca80719da481cc6dd66'))
        );
        $this->authenticateIncomingMsg($message, 'maplesyrup')->shouldBeEqualTo($message);
    }

    function it_should_authenticate_an_incoming_message_with_sha384()
    {
        $this->beConstructedWith('sha384');
        $message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', hex2bin('3bd5d0778d96ecf4179eb98ec3afff423dad2c2ea4dfd8efd2b970bd24b184f4'))
        );
        $this->authenticateIncomingMsg($message, 'maplesyrup')->shouldBeEqualTo($message);
    }

    function it_should_authenticate_an_incoming_message_with_sha512()
    {
        $this->beConstructedWith('sha512');
        $message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', hex2bin('2c1c10a4e405f1b63749c7c6adb5025cd7f0ab9a26a3001c34ca8e5c3e895f1c98a07b12308dcb9d9c389b7395ed098f'))
        );
        $this->authenticateIncomingMsg($message, 'maplesyrup')->shouldBeEqualTo($message);
    }

    function it_should_throw_an_authentication_exception_if_the_received_digest_is_the_wrong_length()
    {
        $this->beConstructedWith('md5');

        $message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', "\x01")
        );
        $this->shouldThrow(new SnmpAuthenticationException('Expected a digest of 12 bytes, but it is 1.'))->during('authenticateIncomingMsg', [$message, 'maplesyrup']);

        $message2 = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', hex2bin('01010101010101010101010101'))
        );
        $this->shouldThrow(new SnmpAuthenticationException('Expected a digest of 12 bytes, but it is 13.'))->during('authenticateIncomingMsg', [$message2, 'maplesyrup']);
    }

    function it_should_throw_an_authentication_exception_if_the_received_digest_is_incorrect()
    {
        $this->beConstructedWith('md5');
        $message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', hex2bin('ac04424fc8acff6b9310a03c'))
        );

        $this->shouldThrow(new SnmpAuthenticationException('The received message contains the wrong digest.'))->during('authenticateIncomingMsg', [$message, 'foobar123']);
    }
}
