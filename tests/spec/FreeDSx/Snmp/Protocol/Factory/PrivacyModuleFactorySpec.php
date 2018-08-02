<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Protocol\Factory;

use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Protocol\Factory\PrivacyModuleFactory;
use FreeDSx\Snmp\Module\Privacy\AESPrivacyModule;
use FreeDSx\Snmp\Module\Privacy\DES3PrivacyModule;
use FreeDSx\Snmp\Module\Privacy\DESPrivacyModule;
use PhpSpec\ObjectBehavior;

class PrivacyModuleFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(PrivacyModuleFactory::class);
    }

    function it_should_get_the_des_based_privacy_module()
    {
        $this->get('des', 1)->shouldBeLike(new DESPrivacyModule('des', 1));
        $this->get('des-cbc', 1)->shouldBeLike(new DESPrivacyModule('des-cbc', 1));
    }

    function it_should_get_the_aes_based_privacy_modules()
    {
        $this->get('aes', 1)->shouldBeLike(new AESPrivacyModule('aes', 1));
        $this->get('aes128',1)->shouldBeLike(new AESPrivacyModule('aes128', 1));
        $this->get('aes192', 1)->shouldBeLike(new AESPrivacyModule('aes192', 1));
        $this->get('aes256', 1)->shouldBeLike(new AESPrivacyModule('aes256', 1));
        $this->get('aes192blu', 1)->shouldBeLike(new AESPrivacyModule('aes192blu', 1));
        $this->get('aes256blu', 1)->shouldBeLike(new AESPrivacyModule('aes256blu', 1));
        $this->get('aes-128-cfb', 1)->shouldBeLike(new AESPrivacyModule('aes-128-cfb', 1));
        $this->get('aes-192-cfb', 1)->shouldBeLike(new AESPrivacyModule('aes-192-cfb', 1));
        $this->get('aes-256-cfb', 1)->shouldBeLike(new AESPrivacyModule('aes-256-cfb', 1));
    }

    function it_should_get_the_3des_based_privacy_module()
    {
        $this->get('3des', 1)->shouldBeAnInstanceOf(new DES3PrivacyModule('3des', 1));
        $this->get('des-ede3-cbc', 1)->shouldBeAnInstanceOf(new DES3PrivacyModule('des-ede3-cbc', 1));
    }

    function it_should_throw_an_exception_if_the_privacy_mechanism_doesnt_exist()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('get', ['bar']);
    }
}
