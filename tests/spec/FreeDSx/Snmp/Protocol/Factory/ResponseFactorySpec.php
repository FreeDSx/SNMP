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
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Protocol\Factory\ResponseFactory;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Response\ReportResponse;
use FreeDSx\Snmp\Response\Response;
use PhpSpec\ObjectBehavior;

class ResponseFactorySpec extends ObjectBehavior
{
    /**
     * @var IncompleteType
     */
    protected $pdu;

    function let()
    {
        $this->pdu = Asn1::sequence(
            Asn1::integer(1),
            Asn1::integer(2),
            Asn1::integer(1),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    OidValues::counter(1)->toAsn1()
                )
            )
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($this->pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $this->pdu = new IncompleteType($pduEncoded);
        $this->pdu = Asn1::context(2, $this->pdu)->setIsConstructed(true);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ResponseFactory::class);
    }

    function it_should_get_the_response_type_object()
    {
        $this->pdu->setTagNumber(2);

        $this::get($this->pdu)->shouldBeAnInstanceOf(Response::class);
    }

    function it_should_get_the_report_response_type_object()
    {
        $this->pdu->setTagNumber(8);

        $this::get($this->pdu)->shouldBeAnInstanceOf(ReportResponse::class);
    }

    function it_should_throw_an_exception_if_the_response_type_is_not_recognized()
    {
        $this->pdu->setTagNumber(99);

        $this->shouldThrow(ProtocolException::class)->during('get', [$this->pdu]);
    }
}
