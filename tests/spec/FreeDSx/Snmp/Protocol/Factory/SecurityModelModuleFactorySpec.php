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

use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Protocol\Factory\SecurityModelModuleFactory;
use FreeDSx\Snmp\Module\SecurityModel\UserSecurityModelModule;
use PhpSpec\ObjectBehavior;

class SecurityModelModuleFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(SecurityModelModuleFactory::class);
    }

    function it_should_get_the_user_security_model()
    {
        $this->get(3)->shouldBeAnInstanceOf(UserSecurityModelModule::class);
    }

    function it_should_throw_an_exception_if_the_security_model_is_not_supported()
    {
        $this->shouldThrow(ProtocolException::class)->during('get', [9000]);
    }
}
