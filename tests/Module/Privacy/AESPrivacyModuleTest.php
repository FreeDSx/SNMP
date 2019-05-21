<?php

declare(strict_types=1);

namespace FreeDSx\Snmp\Module\Privacy;

use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModule;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Request\GetRequest;
use function hex2bin;
use PHPUnit\Framework\TestCase;

final class AESPrivacyModuleTest extends TestCase
{
    /** @var MessageRequestV3 */
    private $message;

    public function setUp() : void
    {
        $this->message = new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo')),
            null,
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 1, 'foo', 'foobar123')
        );

        parent::setUp();
    }
    public function test__it_should_encrypt_data_using_aes128() : void
    {
        $aesPrivacyModule = new AESPrivacyModule('aes128', 900);
        $aesPrivacyModule->encryptData($this->message, new AuthenticationModule('sha1'), 'foobar123');
        self::assertEquals(
            hex2bin('40790d9d2b48450fb731050074b9cad79c30572531da8db2af86ed'),
            $this->message->getEncryptedPdu()
        );

        $aesPrivacyModule->encryptData($this->message, new AuthenticationModule('sha1'), 'foobar123');
        self::assertEquals(
            hex2bin('0000000000000385'),
            $this->message->getSecurityParameters()->getPrivacyParams()
        );
    }
}
