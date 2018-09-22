<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Module\Privacy;

use FreeDSx\Snmp\Exception\SnmpEncryptionException;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModule;
use FreeDSx\Snmp\Module\Privacy\DESPrivacyModule;
use FreeDSx\Snmp\Module\Privacy\PrivacyModuleInterface;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Response\Response;
use PhpSpec\ObjectBehavior;

class DESPrivacyModuleSpec extends ObjectBehavior
{
    protected $request;

    protected $response;

    function let()
    {
        $this->request = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );
        $this->response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduResponse(new Response(0, 0, 0)),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );
        $this->beConstructedWith('des');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(DESPrivacyModule::class);
    }


    function it_should_implement_the_privacy_module_interface()
    {
        $this->shouldImplement(PrivacyModuleInterface::class);
    }

    function it_should_get_the_supported_algorithms()
    {
        $this::supports()->shouldBeEqualTo([
            'des',
            'des-cbc',
        ]);
    }

    function it_should_encrypt_data_using_des()
    {
        $this->beConstructedWith('des', 900);
        $this->encryptData($this->request, new AuthenticationModule('sha1'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('5e2b8c7bffbb23e13d57f9dfa6d80c01734bb339f7873c6b94ef5f73dd625c374ff3bd78b0d1d8d9'));
        $this->encryptData($this->request, new AuthenticationModule('sha1'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000100000385'));
    }

    function it_should_encrypt_a_response_using_des()
    {
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduResponse(new Response(0, 0, 0), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );
        $this->beConstructedWith('des', 900);
        $this->encryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('5e2b8c7bffbb23e1c3245c325c93051f89bc1da953ff408ce780ed43e3956a842befecbabe63676d'));
        $this->encryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000100000385'));
    }

    function it_should_decrypt_data_using_des()
    {
        $this->beConstructedWith('des', 900);
        $this->request->setEncryptedPdu(hex2bin('5e2b8c7bffbb23e13d57f9dfa6d80c01734bb339f7873c6b94ef5f73dd625c374ff3bd78b0d1d8d9'));
        $this->request->getSecurityParameters()->setPrivacyParams(hex2bin('0000000100000384'));

        # The additional data at the end is due to RFC 3414, 8.1.1.2. The padding is ignored while decoding.
        $this->decryptData($this->request, new AuthenticationModule('sha1'),'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduRequest(
            new GetRequest(new OidList()),
            EngineId::fromText('foo')
        ));
    }

    function it_should_decrypt_a_response_using_des()
    {
        $this->beConstructedWith('des', 900);
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            null,
            hex2bin('5e2b8c7bffbb23e1c3245c325c93051f89bc1da953ff408ce780ed43e3956a842befecbabe63676d'),
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123', hex2bin('0000000100000384'))
        );

        $this->decryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduResponse(
            new Response(0),
            EngineId::fromText('foo')
        ));
    }

    function it_should_require_that_the_privacy_password_be_at_least_8_characters()
    {
        $this->shouldThrow(SnmpEncryptionException::class)->during('encryptData', [$this->request, new AuthenticationModule('sha1'), 'foobar1']);
    }

    function it_should_throw_an_SnmpEncryptionException_if_the_encrypted_data_is_malformed()
    {
        $this->request->setEncryptedPdu(hex2bin('ffaabb7bffbb23e13d57f9dfa6d80c01734bb339f7873c6b94ef5f73dd625c374ff3bd78b0d1d8d9'));
        $this->request->getSecurityParameters()->setPrivacyParams(hex2bin('0000000100000384'));

        $this->shouldThrow(new SnmpEncryptionException('Failed to assemble decrypted PDU.'))->during('decryptData', [$this->request,  new AuthenticationModule('md5'),'foobar123']);
    }
}
