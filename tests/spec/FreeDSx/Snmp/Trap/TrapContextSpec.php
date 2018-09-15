<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Trap;

use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Trap\TrapContext;
use PhpSpec\ObjectBehavior;

class TrapContextSpec extends ObjectBehavior
{
    protected $scopedPdu;

    function let()
    {
        $this->scopedPdu = new ScopedPduRequest(new TrapV2Request(OidValues::timeticks(2), OidValues::oid('1.2.3'), new OidList(
            Oid::fromCounter('1.2.3.4', 5)
        )));
        $this->beConstructedWith('192.168.1.1', 3, new MessageRequestV3(
            new MessageHeader(1, MessageHeader::FLAG_AUTH_PRIV, 3),
            $this->scopedPdu
        ));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(TrapContext::class);
    }

    function it_should_get_the_IP_address_the_trap_originated_from()
    {
        $this->getIpAddress()->shouldBeEqualTo('192.168.1.1');
    }

    function it_should_get_the_snmp_version_of_the_incoming_trap()
    {
        $this->getVersion()->shouldBeEqualTo(3);
    }

    function it_should_get_the_complete_SNMP_message()
    {
        $this->getMessage()->shouldBeAnInstanceOf(MessageRequestV3::class);
    }

    function it_should_get_the_trap_request()
    {
        $this->getTrap()->shouldBeLike(new TrapV2Request(OidValues::timeticks(2), OidValues::oid('1.2.3'), new OidList(
            Oid::fromCounter('1.2.3.4', 5)
        )));
    }

    function it_should_check_when_the_trap_is_a_v1_trap()
    {
        $this->isTrapV1()->shouldBeEqualTo(false);
    }

    function it_should_check_when_the_trap_is_not_a_v1_trap()
    {
        $this->scopedPdu->setRequest(new TrapV1Request('1.2.3', OidValues::ipAddress('192.168.1.1'), 1, 2, OidValues::timeticks(1), new OidList()));
        $this->isTrapV1()->shouldBeEqualTo(true);
    }

    function it_should_check_when_the_trap_is_a_v2_trap()
    {
        $this->isTrapV2()->shouldBeEqualTo(true);
    }

    function it_should_check_when_the_trap_is_not_a_v2_trap()
    {
        $this->scopedPdu->setRequest(new TrapV1Request('1.2.3', OidValues::ipAddress('192.168.1.1'), 1, 2, OidValues::timeticks(1), new OidList()));
        $this->isTrapV2()->shouldBeEqualTo(false);
    }

    function it_should_check_when_the_trap_is_not_an_inform_request()
    {
        $this->isInformRequest()->shouldBeEqualTo(false);
    }

    function it_should_check_when_the_trap_is_an_inform_request()
    {
        $this->scopedPdu->setRequest(new InformRequest(OidValues::timeticks(1), OidValues::oid('1.2.3'), new OidList()));
        $this->isInformRequest()->shouldBeEqualTo(true);
    }
}
