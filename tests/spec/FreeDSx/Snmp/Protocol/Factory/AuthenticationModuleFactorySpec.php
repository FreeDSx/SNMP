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
use FreeDSx\Snmp\Protocol\Factory\AuthenticationModuleFactory;
use FreeDSx\Snmp\Module\Authentication\AuthenticationModule;
use PhpSpec\ObjectBehavior;

class AuthenticationModuleFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(AuthenticationModuleFactory::class);
    }

    function it_should_get_the_auth_module_for_md5()
    {
        $this->get('md5')->shouldBeLike(new AuthenticationModule('md5'));
    }

    function it_should_get_the_auth_module_for_sha1()
    {
        $this->get('sha1')->shouldBeLike(new AuthenticationModule('sha1'));
    }

    function it_should_get_the_auth_module_for_sha224()
    {
        $this->get('sha224')->shouldBeLike(new AuthenticationModule('sha224'));
    }

    function it_should_get_the_auth_module_for_sha256()
    {
        $this->get('sha256')->shouldBeLike(new AuthenticationModule('sha256'));
    }

    function it_should_get_the_auth_module_for_sha384()
    {
        $this->get('sha384')->shouldBeLike(new AuthenticationModule('sha384'));
    }

    function it_should_get_the_auth_module_for_sha512()
    {
        $this->get('sha512')->shouldBeLike(new AuthenticationModule('sha512'));
    }

    function it_should_throw_an_exception_for_an_auth_module_that_doesnt_exist()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('get', ['bar']);
    }
}
