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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Protocol\Factory\SecurityParametersFactory;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use PhpSpec\ObjectBehavior;

class SecurityParametersFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(SecurityParametersFactory::class);
    }

    function it_should_get_the_USM_security_parameters()
    {
        $this::get(3, Asn1::octetString((new SnmpEncoder())->encode(Asn1::sequence(
            Asn1::octetString(EngineId::fromText('foobar')->toBinary()),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::octetString('foo'),
            Asn1::octetString(''),
            Asn1::octetString('')
        ))))->shouldBeAnInstanceOf(UsmSecurityParameters::class);
    }

    function it_should_set_the_security_parameters_for_a_class()
    {
        $class = new class implements SecurityParametersInterface {
            public function toAsn1(): AbstractType{}
            public static function fromAsn1(AbstractType $type){
                return new self();
            }
            public function getSecurityModel(): int
            {
                return 99;
            }
        };

        $this::set(get_class($class));
        $this::get(99, Asn1::octetString(''))->shouldBeAnInstanceOf($class);
    }

    function it_should_throw_an_exception_if_the_security_model_is_not_recognized()
    {
        $this->shouldThrow(ProtocolException::class)->during('get', [4, Asn1::octetString('')]);
    }
}
