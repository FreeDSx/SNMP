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
use FreeDSx\Snmp\Module\Privacy\AESPrivacyModule;
use FreeDSx\Snmp\Module\Privacy\PrivacyModuleInterface;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Response\Response;
use PhpSpec\ObjectBehavior;

class AESPrivacyModuleSpec extends ObjectBehavior
{
    protected $message;

    protected $encodedPdu;

    function let()
    {
        $this->encodedPdu = hex2bin('301904088000cd5404666f6f0400a00b0201000201000201003000');
        $this->message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );
        $this->beConstructedWith('aes128');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(AESPrivacyModule::class);
    }

    function it_should_implement_the_privacy_module_interface()
    {
        $this->shouldImplement(PrivacyModuleInterface::class);
    }

    function it_should_get_the_supported_algorithms()
    {
        $this::supports()->shouldBeEqualTo([
            'aes',
            'aes128',
            'aes192',
            'aes256',
            'aes192blu',
            'aes256blu',
            'aes-128-cfb',
            'aes-192-cfb',
            'aes-256-cfb',
        ]);
    }

    function it_should_encrypt_a_response_using_aes()
    {
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduResponse(new Response(0, 0, 0), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );
        $this->beConstructedWith('aes128', 900);
        $this->encryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('40790d9d2b48450fb731050074b9c8d711af0fdd9a15b31a112511'));
        $this->encryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes128()
    {
        $this->beConstructedWith('aes128', 900);
        $this->encryptData($this->message, new AuthenticationModule('sha1'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin("40790d9d2b48450fb731050074b9cad79c30572531da8db2af86ed"));
        $this->encryptData($this->message, new AuthenticationModule('sha1'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes192()
    {
        $this->beConstructedWith('aes192', 900);
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('f5f761cdb2cdeb79a1db7d971ab626c3228d730d1efebe486f4af0'));
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes256()
    {
        $this->beConstructedWith('aes256', 900);
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('fffbd984708e6310ed17681bcc2bfc07cc79aa9499d679d46b1238'));
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes192_blumenthal()
    {
        $this->beConstructedWith('aes192blu', 900);
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('d35520d01a5c6b4530c1493ac94dc3f7abccd563d17e3e4a593376'));
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes256_blumenthal()
    {
        $this->beConstructedWith('aes256blu', 900);
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('a195268db1b257df4ce2510b556f7104f06867ec0989b758bb9405'));
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_decrypt_a_response_using_aes()
    {
        $this->beConstructedWith('aes128', 900);
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            null,
            hex2bin('40790d9d2b48450fb731050074b9c8d711af0fdd9a15b31a112511'),
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123', hex2bin('0000000000000384'))
        );

        $this->decryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduResponse(
            new Response(0),
            EngineId::fromText('foo')
        ));
    }

    function it_should_decrypt_data_using_aes128()
    {
        $this->beConstructedWith('aes128', 900);
        $this->message->setEncryptedPdu(hex2bin('40790d9d2b48450fb731050074b9cad79c30572531da8db2af86ed'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('sha1'),'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduRequest(
            new GetRequest(new OidList()),
            EngineId::fromText('foo')
        ));
    }

    function it_should_decrypt_data_using_aes192()
    {
        $this->beConstructedWith('aes192', 900);
        $this->message->setEncryptedPdu(hex2bin('f5f761cdb2cdeb79a1db7d971ab626c3228d730d1efebe486f4af0'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('md5'),'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduRequest(
            new GetRequest(new OidList()),
            EngineId::fromText('foo')
        ));
    }

    function it_should_decrypt_data_using_aes256()
    {
        $this->beConstructedWith('aes256', 900);
        $this->message->setEncryptedPdu(hex2bin('fffbd984708e6310ed17681bcc2bfc07cc79aa9499d679d46b1238'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('md5'),'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduRequest(
            new GetRequest(new OidList()),
            EngineId::fromText('foo')
        ));
    }

    function it_should_decrypt_data_using_aes192_blumenthal()
    {
        $this->beConstructedWith('aes192blu', 900);
        $this->message->setEncryptedPdu(hex2bin('d35520d01a5c6b4530c1493ac94dc3f7abccd563d17e3e4a593376'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('md5'),'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduRequest(
            new GetRequest(new OidList()),
            EngineId::fromText('foo')
        ));
    }

    function it_should_decrypt_data_using_aes256_blumenthal()
    {
        $this->beConstructedWith('aes256blu', 900);
        $this->message->setEncryptedPdu(hex2bin('a195268db1b257df4ce2510b556f7104f06867ec0989b758bb9405'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('md5'),'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduRequest(
            new GetRequest(new OidList()),
            EngineId::fromText('foo')
        ));
    }

    function it_should_require_that_the_privacy_password_be_at_least_8_characters()
    {
        $this->shouldThrow(SnmpEncryptionException::class)->during('encryptData', [$this->message, new AuthenticationModule('sha1'), 'foobar1']);
    }

    function it_should_throw_an_SnmpEncryptionException_if_the_encrypted_data_is_malformed()
    {
        $this->message->setEncryptedPdu(hex2bin('ffbbaa8db1b257df4ce2510b556f7104f06867ec0989b758bb9405'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->shouldThrow(new SnmpEncryptionException('Failed to assemble decrypted PDU.'))->during('decryptData', [$this->message,  new AuthenticationModule('md5'),'foobar123']);
    }
}
