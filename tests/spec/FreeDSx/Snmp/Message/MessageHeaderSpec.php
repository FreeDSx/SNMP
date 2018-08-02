<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Message;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use PhpSpec\ObjectBehavior;

class MessageHeaderSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(MessageHeader::class);
    }

    function it_should_implement_protocol_element_interface()
    {
        $this->shouldImplement(ProtocolElementInterface::class);
    }

    function it_should_get_the_id()
    {
        $this->getId()->shouldBeEqualTo(1);
    }

    function it_should_set_the_id()
    {
        $this->setId(2);
        $this->getId()->shouldBeEqualTo(2);
    }

    function it_should_get_the_max_size()
    {
        $this->getMaxSize()->shouldBeEqualTo(65507);
    }

    function it_should_set_the_max_size()
    {
        $this->setMaxSize(9000);
        $this->getMaxSize()->shouldBeEqualTo(9000);
    }

    function it_should_get_the_security_model()
    {
        $this->getSecurityModel()->shouldBeEqualTo(3);
    }

    function it_should_set_the_security_model()
    {
        $this->setSecurityModel(4);
        $this->getSecurityModel()->shouldBeEqualTo(4);
    }

    function it_should_get_the_flags()
    {
        $this->getFlags()->shouldBeEqualTo(MessageHeader::FLAG_NO_AUTH_NO_PRIV);
    }

    function it_should_set_the_flags()
    {
        $this->setFlags(MessageHeader::FLAG_AUTH);
        $this->getFlags()->shouldBeEqualTo(MessageHeader::FLAG_AUTH);
    }

    function it_should_add_a_flag()
    {
        $this->addFlag(MessageHeader::FLAG_AUTH);
        $this->addFlag(MessageHeader::FLAG_PRIV);
        $this->getFlags()->shouldBeEqualTo(MessageHeader::FLAG_AUTH_PRIV);
    }

    function it_should_check_if_it_has_a_flag()
    {
        $this->hasFlag(MessageHeader::FLAG_AUTH)->shouldBeEqualTo(false);
        $this->hasFlag(MessageHeader::FLAG_PRIV)->shouldBeEqualTo(false);

        $this->addFlag(MessageHeader::FLAG_AUTH);

        $this->hasFlag(MessageHeader::FLAG_AUTH)->shouldBeEqualTo(true);
    }

    function it_should_check_if_it_has_privacy()
    {
        $this->hasPrivacy()->shouldBeEqualTo(false);
        $this->addFlag(MessageHeader::FLAG_PRIV);
        $this->hasPrivacy()->shouldBeEqualTo(true);
    }

    function it_should_check_if_it_has_authentication()
    {
        $this->hasAuthentication()->shouldBeEqualTo(false);
        $this->addFlag(MessageHeader::FLAG_AUTH);
        $this->hasAuthentication()->shouldBeEqualTo(true);
    }

    function it_should_check_if_it_is_reportable()
    {
        $this->isReportable()->shouldBeEqualTo(false);
        $this->addFlag(MessageHeader::FLAG_REPORTABLE);
        $this->isReportable()->shouldBeEqualTo(true);
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
           Asn1::integer(1),
           Asn1::integer(65507),
           Asn1::octetString("\x00"),
           Asn1::integer(3)
        ));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $this::fromAsn1(Asn1::sequence(
            Asn1::integer(1),
            Asn1::integer(65507),
            Asn1::octetString("\x00"),
            Asn1::integer(3)
        ))->shouldBeLike(new MessageHeader(1));
    }
}
