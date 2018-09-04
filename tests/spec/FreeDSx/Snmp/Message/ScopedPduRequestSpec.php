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
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Message\ScopedPdu;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Protocol\ProtocolElementInterface;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Response\ResponseInterface;
use PhpSpec\ObjectBehavior;

class ScopedPduRequestSpec extends ObjectBehavior
{
    function let(RequestInterface $request)
    {
        $request->beADoubleOf(Pdu::class);
        $request->toAsn1()->willReturn(Asn1::sequence());

        $this->beConstructedWith($request);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ScopedPduRequest::class);
    }

    function it_should_implement_protocol_element_interface()
    {
        $this->shouldImplement(ProtocolElementInterface::class);
    }

    function it_should_be_an_instance_of_scoped_pdu()
    {
        $this->shouldBeAnInstanceOf(ScopedPdu::class);
    }

    function it_should_only_allow_a_request_pdu(ResponseInterface $response)
    {
        $this->beConstructedWith($response);
        $this->shouldThrow(\Throwable::class)->duringInstantiation();
    }

    function it_should_get_the_request_pdu($request)
    {
        $this->getRequest()->shouldBeEqualTo($request);
    }

    function it_should_set_the_request_pdu(RequestInterface $newRequest)
    {
        $this->setRequest($newRequest);

        $this->getRequest()->shouldBeEqualTo($newRequest);
    }

    function it_should_get_the_context_name()
    {
        $this->getContextName()->shouldBeEqualTo('');
    }

    function it_should_set_the_context_name()
    {
        $this->setContextName('foo');

        $this->getContextName()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_context_engine_id()
    {
        $this->getContextEngineId()->shouldBeNull();
    }

    function it_should_set_the_context_engine_id()
    {
        $this->setContextEngineId(EngineId::fromText('foo'));
        $this->getContextEngineId()->shouldBeAnInstanceOf(EngineId::class);
    }

    function it_should_have_an_ASN1_representation($request)
    {
        $request->toAsn1()->shouldBeCalled();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(''),
            Asn1::octetString(''),
            Asn1::sequence()
        ));
    }

    function it_should_be_constructed_from_an_ASN1_representation()
    {
        $pdu = Asn1::sequence(
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::sequenceOf()
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $pdu = Asn1::context(0, $pdu)->setIsConstructed(true);

        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(EngineId::fromText('foo')->toBinary()),
            Asn1::octetString('bar'),
            $pdu
        ))->shouldBeLike(new ScopedPduRequest(new GetRequest(new OidList()), EngineId::fromText('foo'), 'bar'));
    }
}
