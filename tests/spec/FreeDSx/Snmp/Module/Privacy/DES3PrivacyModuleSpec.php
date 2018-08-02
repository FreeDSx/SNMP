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
use FreeDSx\Snmp\Module\Privacy\DES3PrivacyModule;
use FreeDSx\Snmp\Module\Privacy\PrivacyModuleInterface;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Request\GetRequest;
use PhpSpec\ObjectBehavior;

class DES3PrivacyModuleSpec extends ObjectBehavior
{
    protected $message;

    function let()
    {
        $this->message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), 'foo'),
            null,
            new UsmSecurityParameters('foo', 1, 1, 'foo', 'foobar123')
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
        $this->encryptData($this->message,  new AuthenticationModule('md5'), 'foobar123')->getEncryptedPdu()->shouldBeEqualTo(hex2bin('95efe6023d80230360515ea5893ba429d15233454dd1c1052c0b88874953efb3'));
        $this->encryptData($this->message,  new AuthenticationModule('md5'), 'foobar123')->getSecurityParameters()->getPrivacyParams()->shouldBeEqualTo(hex2bin('9ea532f311f223b1'));
    }

    function it_should_decrypt_data_using_3des()
    {
        $this->beConstructedWith('3des', 900);
        $this->message->setEncryptedPdu(hex2bin('95efe6023d80230360515ea5893ba429d15233454dd1c1052c0b88874953efb3'));
        $this->message->getSecurityParameters()->setPrivacyParams(hex2bin('a50e78b737b4a2a9'));

        # The additional data at the end is due to RFC 3414, 8.1.1.2. The padding is ignored while decoding.
        $this->decryptData($this->message,  new AuthenticationModule('md5'), 'foobar123')->shouldBeEqualTo(
            hex2bin('30140403666f6f0400a00b020100020100020100300000000808080808080808')
        );
    }

    function it_should_require_that_the_privacy_password_be_at_least_8_characters()
    {
        $this->shouldThrow(SnmpEncryptionException::class)->during('encryptData', [$this->message, new AuthenticationModule('md5'), 'foobar1']);
    }
}
