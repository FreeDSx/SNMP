<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Message\Security;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use PhpSpec\ObjectBehavior;

class UsmSecurityParametersSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(EngineId::fromText('foo'), 1, 2, 'bar', 'auth', 'priv');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(UsmSecurityParameters::class);
    }

    function it_should_implement_the_security_parameters_interface()
    {
        $this->shouldImplement(SecurityParametersInterface::class);
    }

    function it_should_get_the_security_model_number()
    {
        $this->getSecurityModel()->shouldBeEqualTo(3);
    }

    function it_should_get_the_engine_id()
    {
        $this->getEngineId()->shouldBeLike(EngineId::fromText('foo'));
    }

    function it_should_get_the_engine_boots()
    {
        $this->getEngineBoots()->shouldBeEqualTo(1);
    }

    function it_should_get_the_engine_time()
    {
        $this->getEngineTime()->shouldBeEqualTo(2);
    }

    function it_should_get_the_username()
    {
        $this->getUsername()->shouldBeEqualTo('bar');
    }

    function it_should_get_the_auth_params()
    {
        $this->getAuthParams()->shouldBeEqualTo('auth');
    }

    function it_should_get_the_priv_params()
    {
        $this->getPrivacyParams()->shouldBeEqualTo('priv');
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(
            Asn1::sequence(
                Asn1::octetString(EngineId::fromText('foo')->toBinary()),
                Asn1::integer(1),
                Asn1::integer(2),
                Asn1::octetString('bar'),
                Asn1::octetString('auth'),
                Asn1::octetString('priv')
            )
        );
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $this::fromAsn1(Asn1::octetString((new SnmpEncoder())->encode(Asn1::sequence(
            Asn1::octetString(EngineId::fromText('foo')->toBinary()),
            Asn1::integer(1),
            Asn1::integer(2),
            Asn1::octetString('bar'),
            Asn1::octetString('auth'),
            Asn1::octetString('priv')
        ))))->shouldBeLike(
            new UsmSecurityParameters(EngineId::fromText('foo'), 1, 2, 'bar', 'auth', 'priv')
        );
    }
}
