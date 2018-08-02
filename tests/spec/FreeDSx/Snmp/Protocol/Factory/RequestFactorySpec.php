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
use FreeDSx\Snmp\Protocol\Factory\RequestFactory;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use FreeDSx\Snmp\Request\GetBulkRequest;
use FreeDSx\Snmp\Request\GetNextRequest;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\SetRequest;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
use PhpSpec\ObjectBehavior;

class RequestFactorySpec extends ObjectBehavior
{
    /**
     * @var IncompleteType
     */
    protected $pdu;

    function let()
    {
        $this->pdu = Asn1::sequence(
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    Asn1::null()
                )
            )
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($this->pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $this->pdu = new IncompleteType($pduEncoded);
        $this->pdu = Asn1::context(0, $this->pdu)->setIsConstructed(true);
    }
    function it_is_initializable()
    {
        $this->shouldHaveType(RequestFactory::class);
    }

    function it_should_get_the_get_request_object()
    {
        $this->pdu->setTagNumber(0);

        $this::get($this->pdu)->shouldBeAnInstanceOf(GetRequest::class);
    }

    function it_should_get_the_get_next_request_object()
    {
        $this->pdu->setTagNumber(1);

        $this::get($this->pdu)->shouldBeAnInstanceOf(GetNextRequest::class);
    }

    function it_should_get_the_bulk_request_object()
    {
        $this->pdu->setTagNumber(5);

        $this::get($this->pdu)->shouldBeAnInstanceOf(GetBulkRequest::class);
    }

    function it_should_get_the_set_request_object()
    {
        $this->pdu->setTagNumber(3);

        $this::get($this->pdu)->shouldBeAnInstanceOf(SetRequest::class);
    }

    function it_should_get_the_trap_v1_request_object()
    {
        $pdu = Asn1::sequence(
            Asn1::oid('1.2.3'),
            OidValues::ipAddress('192.168.1.1')->toAsn1(),
            Asn1::integer(1),
            Asn1::integer(2),
            OidValues::timeticks(1)->toAsn1(),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.2.3'),
                    OidValues::counter(1)->toAsn1()
                )
            )
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $pdu = Asn1::context(4, $pdu)->setIsConstructed(true);

        $this::get($pdu)->shouldBeAnInstanceOf(TrapV1Request::class);
    }

    function it_should_get_trap_v2_request_object()
    {
        $pdu = Asn1::sequence(
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.3.6.1.2.1.1.3.0'),
                    OidValues::timeticks(1)->toAsn1()
                ),
                Asn1::sequence(
                    Asn1::oid('1.3.6.1.6.3.1.1.4.1.0'),
                    OidValues::oid('1.2.3')->toAsn1()
                ),
                Asn1::sequence(
                    Asn1::oid('1.2'),
                    OidValues::integer(1)->toAsn1()
                )
            )
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $pdu = Asn1::context(7, $pdu)->setIsConstructed(true);

        $this::get($pdu)->shouldBeAnInstanceOf(TrapV2Request::class);
    }

    function it_should_get_the_inform_request_object()
    {
        $pdu = Asn1::sequence(
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::oid('1.3.6.1.2.1.1.3.0'),
                    OidValues::timeticks(1)->toAsn1()
                ),
                Asn1::sequence(
                    Asn1::oid('1.3.6.1.6.3.1.1.4.1.0'),
                    OidValues::oid('1.2.3')->toAsn1()
                ),
                Asn1::sequence(
                    Asn1::oid('1.2'),
                    OidValues::integer(1)->toAsn1()
                )
            )
        );

        $encoder = new SnmpEncoder();
        $pduEncoded = '';
        foreach ($pdu as $element) {
            $pduEncoded .= $encoder->encode($element);
        }

        $pdu = new IncompleteType($pduEncoded);
        $pdu = Asn1::context(6, $pdu)->setIsConstructed(true);

        $this::get($pdu)->shouldBeAnInstanceOf(InformRequest::class);
    }

    function it_should_throw_an_exception_if_the_request_type_is_not_recognized()
    {
        $this->pdu->setTagNumber(99);

        $this->shouldThrow(ProtocolException::class)->during('get', [$this->pdu]);
    }
}
