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
use FreeDSx\Snmp\SnmpClient;
use FreeDSx\Snmp\SnmpWalk;
use PhpSpec\ObjectBehavior;

class SnmpWalkSpec extends ObjectBehavior
{
    function let(SnmpClient $client)
    {
        $this->beConstructedWith($client);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SnmpWalk::class);
    }

    function it_should_start_at_a_default_oid($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1')));
        $this->next();
    }

    function it_should_start_at_a_specific_oid($client)
    {
        $this->beConstructedWith($client, '1.3.6.1.2.2');
        $client->getNext('1.3.6.1.2.2')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));
        $this->next();
    }

    function it_should_end_at_a_specific_oid($client)
    {
        $this->beConstructedWith($client, null, '1.3.6.1.2.2');

        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->next();
        $this->hasOids()->shouldBeEqualTo(false);
    }

    function it_should_restart_the_walk($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled(2)->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->next();
        $this->restart();
        $this->next();
    }

    function it_should_skip_to_a_specific_oid($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));
        $client->getNext('1.3.6.1.2.5')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.6')));

        $this->next();
        $this->skipTo('1.3.6.1.2.5');
        $this->next();
    }

    function it_should_get_the_next_oid($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->next()->shouldBeLike(new Oid('1.3.6.1.2.2'));
    }

    function it_should_return_as_complete_if_the_last_oid_returned_had_a_status_as_the_end_of_the_mib_view($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2', null, Oid::STATUS_END_OF_MIB_VIEW)));

        $this->next();
        $this->isComplete()->shouldBeEqualTo(true);
    }

    function it_should_return_whether_the_walk_is_complete($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->isComplete()->shouldBeEqualTo(false);
        $this->next();
        $this->isComplete()->shouldBeEqualTo(false);
    }

    function it_should_return_whether_there_are_oids_remaining_in_the_walk($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->hasOids()->shouldBeEqualTo(true);
        $this->next();
        $this->hasOids()->shouldBeEqualTo(true);
    }

    function it_should_get_the_count($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));
        $client->getNext('1.3.6.1.2.2')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.3')));

        $this->count()->shouldBeEqualTo(0);
        $this->next();
        $this->count()->shouldBeEqualTo(1);
        $this->next();
        $this->count()->shouldBeEqualTo(2);
    }

    function it_should_reset_the_count_when_restart_is_called($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->count()->shouldBeEqualTo(0);
        $this->next();
        $this->count()->shouldBeEqualTo(1);
        $this->restart();
        $this->count()->shouldBeEqualTo(0);
    }
}