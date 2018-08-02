<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Message\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Message\AbstractMessageV3;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Message\Security\SecurityParametersInterface;
use FreeDSx\Snmp\Message\Security\UsmSecurityParameters;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetRequest;
use PhpSpec\ObjectBehavior;

class MessageRequestV3Spec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(
            new MessageHeader(0),
            new ScopedPduRequest(new GetRequest(new OidList())),
            null,
            new UsmSecurityParameters()
        );
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(MessageRequestV3::class);
    }

    function it_should_implement_MessageRequestInterface()
    {
        $this->shouldImplement(MessageRequestInterface::class);
    }

    function it_should_extend_abstract_message_v3()
    {
        $this->shouldBeAnInstanceOf(AbstractMessageV3::class);
    }

    function it_should_get_the_version()
    {
        $this->getVersion()->shouldBeEqualTo(3);
    }

    function it_should_get_the_message_header()
    {
        $this->getMessageHeader()->shouldBeAnInstanceOf(MessageHeader::class);
    }

    function it_should_get_the_security_parameters()
    {
        $this->getSecurityParameters()->shouldBeAnInstanceOf(SecurityParametersInterface::class);
    }

    function it_should_get_the_scoped_pdu_request()
    {
        $this->getScopedPdu()->shouldBeAnInstanceOf(ScopedPduRequest::class);
    }

    function it_should_get_the_encrypted_pdu()
    {
        $this->getEncryptedPdu()->shouldBeNull();
    }

    function it_should_have_an_ASN1_representation()
    {
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::integer(3),
            (new MessageHeader(0))->toAsn1(),
            Asn1::octetString((new SnmpEncoder())->encode((new UsmSecurityParameters())->toAsn1())),
            (new ScopedPduRequest(new GetRequest(new OidList())))->toAsn1()
        ));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $encoder = new SnmpEncoder();

        $pdu = '';
        foreach ((new GetRequest(new OidList()))->toAsn1() as $child) {
            $pdu .= $encoder->encode($child);
        }

        $this::fromAsn1(Asn1::sequence(
            Asn1::integer(3),
            (new MessageHeader(0, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3))->toAsn1(),
            Asn1::octetString((new SnmpEncoder())->encode((new UsmSecurityParameters())->toAsn1())),
            Asn1::sequence(
                Asn1::octetString(''),
                Asn1::octetString(''),
                Asn1::context(0, new IncompleteType($pdu))->setIsConstructed(true)
            )
        ))->shouldBeLike(
            new MessageRequestV3(
                new MessageHeader(0, MessageHeader::FLAG_NO_AUTH_NO_PRIV, 3),
                new ScopedPduRequest(new GetRequest(new OidList())),
                null,
                new UsmSecurityParameters()
            )
        );
    }
}
