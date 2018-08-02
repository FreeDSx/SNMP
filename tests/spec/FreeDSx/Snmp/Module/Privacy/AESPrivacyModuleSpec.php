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
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModule;
use FreeDSx\Snmp\Module\Privacy\AESPrivacyModule;
use FreeDSx\Snmp\Module\Privacy\PrivacyModuleInterface;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Request\GetRequest;
use PhpSpec\ObjectBehavior;

class AESPrivacyModuleSpec extends ObjectBehavior
{
    protected $message;

    protected $encodedPdu;

    function let()
    {
        $this->encodedPdu = hex2bin('30140403666f6f0400a00b0201000201000201003000');
        $this->message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), 'foo'),
            null,
            new UsmSecurityParameters('foo', 1, 1, 'foo', 'foobar123')
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

    function it_should_encrypt_data_using_aes128()
    {
        $this->beConstructedWith('aes128', 900);
        $this->encryptData($this->message, new AuthenticationModule('sha1'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('67889ff865a14762d876cb5ddb640ff582681461bec6'));
        $this->encryptData($this->message, new AuthenticationModule('sha1'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes192()
    {
        $this->beConstructedWith('aes192', 900);
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('753dd6b9e7de95f238c8b50f5d9c8a9f9a997b9a56b4'));
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes256()
    {
        $this->beConstructedWith('aes256', 900);
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('a4b15da81853d1b0a5a2c2814859f2f6252bd67a4e26'));
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes192_blumenthal()
    {
        $this->beConstructedWith('aes192blu', 900);
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('7ea230f868a340aea321a3ef7b5dd3113d750b56bd76'));
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_encrypt_data_using_aes256_blumenthal()
    {
        $this->beConstructedWith('aes256blu', 900);
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('51a3ef983c7f0f4a4bcc285e57aa9b699e899d249e73'));
        $this->encryptData($this->message, new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('0000000000000385'));
    }

    function it_should_decrypt_data_using_aes128()
    {
        $this->beConstructedWith('aes128', 900);
        $this->message->setEncryptedPdu(hex2bin('67889ff865a14762d876cb5ddb640ff582681461bec6'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('sha1'),'foobar123')->shouldBeEqualTo($this->encodedPdu);
    }

    function it_should_decrypt_data_using_aes192()
    {
        $this->beConstructedWith('aes192', 900);
        $this->message->setEncryptedPdu(hex2bin('753dd6b9e7de95f238c8b50f5d9c8a9f9a997b9a56b4'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('md5'),'foobar123')->shouldBeEqualTo($this->encodedPdu);
    }

    function it_should_decrypt_data_using_aes256()
    {
        $this->beConstructedWith('aes256', 900);
        $this->message->setEncryptedPdu(hex2bin('a4b15da81853d1b0a5a2c2814859f2f6252bd67a4e26'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('md5'),'foobar123')->shouldBeEqualTo($this->encodedPdu);
    }

    function it_should_decrypt_data_using_aes192_blumenthal()
    {
        $this->beConstructedWith('aes192blu', 900);
        $this->message->setEncryptedPdu(hex2bin('7ea230f868a340aea321a3ef7b5dd3113d750b56bd76'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('md5'),'foobar123')->shouldBeEqualTo($this->encodedPdu);
    }

    function it_should_decrypt_data_using_aes256_blumenthal()
    {
        $this->beConstructedWith('aes256blu', 900);
        $this->message->setEncryptedPdu(hex2bin('51a3ef983c7f0f4a4bcc285e57aa9b699e899d249e73'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('0000000000000384'));

        $this->decryptData($this->message,  new AuthenticationModule('md5'),'foobar123')->shouldBeEqualTo($this->encodedPdu);
    }

    function it_should_require_that_the_privacy_password_be_at_least_8_characters()
    {
        $this->shouldThrow(SnmpEncryptionException::class)->during('encryptData', [$this->message, new AuthenticationModule('sha1'), 'foobar1']);
    }
}
