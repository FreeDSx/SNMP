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
use FreeDSx\Snmp\Module\Privacy\DES3PrivacyModule;
use FreeDSx\Snmp\Module\Privacy\PrivacyModuleInterface;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Response\Response;
use PhpSpec\ObjectBehavior;

class DES3PrivacyModuleSpec extends ObjectBehavior
{
    protected $message;

    function let()
    {
        $this->message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );
        $this->beConstructedWith('3des');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(DES3PrivacyModule::class);
    }


    function it_should_implement_the_privacy_module_interface()
    {
        $this->shouldImplement(PrivacyModuleInterface::class);
    }

    function it_should_get_the_supported_algorithms()
    {
        $this::supports()->shouldBeEqualTo([
            '3des',
            'des-ede3-cbc',
        ]);
    }

    function it_should_encrypt_data_using_3des()
    {
        $this->beConstructedWith('3des', 900);
        $this->encryptData($this->message,  new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('46f2b79595ab1499b3602d846163773f4e91ac9b17f6547ed2f84db19fda1ca42adbdd3fed8bb908'));
        $this->encryptData($this->message,  new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('3f1bc9b7ef5fb879'));
    }

    function it_should_encrypt_a_response_using_3des()
    {
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduResponse(new Response(0, 0, 0), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );
        $this->beConstructedWith('3des', 900);
        $this->encryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('5649df94a907aa48bfe6e074c5b3cbc7f2840a219bd175e0d33a4163f8a8d1637dba55a2665fc356'));
        $this->encryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('4c78e4388e4f93b9'));
    }

    function it_should_decrypt_data_using_3des()
    {
        $this->beConstructedWith('3des', 900);
        $this->message->setEncryptedPdu(hex2bin('46f2b79595ab1499b3602d846163773f4e91ac9b17f6547ed2f84db19fda1ca42adbdd3fed8bb908'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('cffb5fcda1e88bf2'));

        # The additional data at the end is due to RFC 3414, 8.1.1.2. The padding is ignored while decoding.
        $this->decryptData($this->message,  new AuthenticationModule('md5'), 'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduRequest(
            new GetRequest(new OidList()),
            EngineId::fromText('foo')
        ));
    }


    function it_should_decrypt_a_response_using_3des()
    {
        $this->beConstructedWith('3des', 900);
        $response = new MessageResponseV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            null,
            hex2bin('5649df94a907aa48bfe6e074c5b3cbc7f2840a219bd175e0d33a4163f8a8d1637dba55a2665fc356'),
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123', hex2bin('fe609d2981ff5a0f'))
        );

        $this->decryptData($response, new AuthenticationModule('sha1'), 'foobar123')->getScopedPdu()->shouldBeLike(new ScopedPduResponse(
            new Response(0),
            EngineId::fromText('foo')
        ));
    }

    function it_should_require_that_the_privacy_password_be_at_least_8_characters()
    {
        $this->shouldThrow(SnmpEncryptionException::class)->during('encryptData', [$this->message, new AuthenticationModule('md5'), 'foobar1']);
    }

    function it_should_throw_an_SnmpEncryptionException_if_the_encrypted_data_is_malformed()
    {
        $this->message->setEncryptedPdu(hex2bin('ffbbaaa595ab1499b3602d846163773f4e91ac9b17f6547ed2f84db19fda1ca42adbdd3fed8bb908'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('cffb5fcda1e88bf2'));

        $this->shouldThrow(new SnmpEncryptionException('Failed to assemble decrypted PDU.'))->during('decryptData', [$this->message,  new AuthenticationModule('md5'),'foobar123']);
    }
}
