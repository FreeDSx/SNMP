<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp;

use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\OidValues;
use FreeDSx\Snmp\Request\GetBulkRequest;
use FreeDSx\Snmp\Request\GetNextRequest;
use FreeDSx\Snmp\Request\GetRequest;
use FreeDSx\Snmp\Request\InformRequest;
use FreeDSx\Snmp\Request\SetRequest;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Requests;
use FreeDSx\Snmp\Value\IntegerValue;
use PhpSpec\ObjectBehavior;

class RequestsSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(Requests::class);
    }

    function it_should_get_a_bulk_request()
    {
        $this::getBulk(1, 2, '1.2.3.4.5')->shouldBeLike(new GetBulkRequest(1, 2, new OidList(new Oid('1.2.3.4.5'))));
    }

    function it_should_get_a_get_request()
    {
        $this::get('1.2.3.4.5')->shouldBeLike(new GetRequest(new OidList(new Oid('1.2.3.4.5'))));
    }

    function it_should_get_a_get_next_request()
    {
        $this::getNext('1.2.3.4.5')->shouldBeLike(new GetNextRequest(new OidList(new Oid('1.2.3.4.5'))));
    }

    function it_should_get_a_set_request()
    {
        $this::set(Oid::fromInteger('1.2.3.4.5', 5))->shouldBeLike(new SetRequest(new OidList(new Oid('1.2.3.4.5', new IntegerValue(5)))));
    }

    function it_should_get_a_trap_v1_request()
    {
        $this::trapV1('foo', '127.0.0.1', 1, 2, 3, new Oid('1.2.3.4.5'))->shouldBeLike(
            new TrapV1Request('foo', OidValues::ipAddress('127.0.0.1'), 1, 2, OidValues::timeticks(3), new OidList(new Oid('1.2.3.4.5')))
        );
    }

    function it_should_get_a_trap_v2_request()
    {
        $this::trap(OidValues::timeticks(1), OidValues::oid('1.2.3.4.5'), Oid::fromCounter('1.2.3.4.5', 1))->shouldBeLike(
            new TrapV2Request(OidValues::timeticks(1), OidValues::oid('1.2.3.4.5'), new OidList(Oid::fromCounter('1.2.3.4.5', 1)))
        );
    }

    function it_should_get_an_inform_request()
    {
        $this::inform(OidValues::timeticks(1), OidValues::oid('1.2.3.4.5'), Oid::fromCounter('1.2.3.4.5', 1))->shouldBeLike(
            new InformRequest(OidValues::timeticks(1), OidValues::oid('1.2.3.4.5'), new OidList(Oid::fromCounter('1.2.3.4.5', 1)))
        );
    }
}
