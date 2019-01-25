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

use FreeDSx\Snmp\Exception\EndOfWalkException;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\SnmpClient;
use FreeDSx\Snmp\SnmpWalk;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SnmpWalkSpec extends ObjectBehavior
{
    function let(SnmpClient $client)
    {
        $client->getOptions()->willReturn(['version' => 1]);
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
        $this->beConstructedWith($client, null, '1.3.6.1.2.1.1');

        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));

        $this->next();
        $this->hasOids()->shouldBeEqualTo(false);
    }

    function it_should_restart_the_walk($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled(2)->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));

        $this->next();
        $this->restart();
        $this->next();
    }

    function it_should_skip_to_a_specific_oid($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));
        $client->getNext('1.3.6.1.2.1.5')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.6')));

        $this->next();
        $this->skipTo('1.3.6.1.2.1.5');
        $this->next();
    }

    function it_should_get_the_next_oid($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));

        $this->next()->shouldBeLike(new Oid('1.3.6.1.2.1.1'));
    }

    function it_should_return_as_complete_if_the_last_oid_returned_had_a_status_as_the_end_of_the_mib_view($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1', null, Oid::STATUS_END_OF_MIB_VIEW)));

        $this->next();
        $this->isComplete()->shouldBeEqualTo(true);
    }

    function it_should_return_whether_the_walk_is_complete($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));
        $client->getNext('1.3.6.1.2.1.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.2')));

        $this->isComplete()->shouldBeEqualTo(false);
        $this->next();
        $this->isComplete()->shouldBeEqualTo(false);
    }

    function it_should_return_whether_there_are_oids_remaining_in_the_walk($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));
        $client->getNext('1.3.6.1.2.1.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.2')));

        $this->hasOids()->shouldBeEqualTo(true);
        $this->next();
        $this->hasOids()->shouldBeEqualTo(true);
    }

    function it_should_get_the_count($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));
        $client->getNext('1.3.6.1.2.1.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.2')));

        $this->count()->shouldBeEqualTo(0);
        $this->next();
        $this->count()->shouldBeEqualTo(1);
        $this->next();
        $this->count()->shouldBeEqualTo(2);
    }

    function it_should_reset_the_count_when_restart_is_called($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));

        $this->count()->shouldBeEqualTo(0);
        $this->next();
        $this->count()->shouldBeEqualTo(1);
        $this->restart();
        $this->count()->shouldBeEqualTo(0);
    }

    function it_should_throw_an_end_of_walk_exception_if_next_is_called_when_there_is_nothing_left($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1', null, Oid::STATUS_END_OF_MIB_VIEW)));
        $this->next();

        $this->isComplete()->shouldBeEqualTo(true);
        $this->shouldThrow(EndOfWalkException::class)->during('next');
    }

    function it_should_determine_whether_or_not_the_end_of_the_subtree_is_reached($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));
        $client->getNext('1.3.6.1.2.1.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->next();
        $this->isComplete()->shouldBeEqualTo(true);
    }

    function it_should_not_stop_at_the_end_of_the_subtree_if_specified($client)
    {
        $this->subtreeOnly(false);
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));
        $client->getNext('1.3.6.1.2.1.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->next();
        $this->isComplete()->shouldBeEqualTo(false);
        $this->next();
        $this->isComplete()->shouldBeEqualTo(false);
    }

    function it_should_return_complete_if_the_first_oid_requested_is_not_within_the_subtree($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.2')));

        $this->isComplete()->shouldBeEqualTo(true);
        $this->hasOids()->shouldBeEqualTo(false);
    }

    function it_should_use_GetBulk_if_the_client_is_set_to_snmp_v2($client)
    {
        $client->getOptions()->willReturn(['version' => 2]);
        $client->getBulk(100, 0, '1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1'), new Oid('1.3.6.1.2.1.2')));

        $this->next()->shouldBeLike(new Oid('1.3.6.1.2.1.1'));
        $this->next()->shouldBeLike(new Oid('1.3.6.1.2.1.2'));

        $client->getBulk(100, 0, '1.3.6.1.2.1.2')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.3')));

        $this->next()->shouldBeLike(new Oid('1.3.6.1.2.1.3'));
    }

    function it_should_use_GetNext_if_use_get_bulk_is_set_to_false($client)
    {
        $client->getOptions()->willReturn(['version' => 2]);
        $this->useGetBulk(false);

        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));
        $client->getBulk(Argument::any(), Argument::any(), Argument::any())->shouldNotBeCalled();
        $this->next();
    }

    function it_should_use_the_specified_max_repetitions($client)
    {
        $client->getOptions()->willReturn(['version' => 3]);
        $client->getBulk(50, 0, '1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1'), new Oid('1.3.6.1.2.1.2')));

        $this->maxRepetitions(50);
        $this->next();
    }

    function it_should_get_the_next_oid_when_calling_getOid($client)
    {
        $client->getNext('1.3.6.1.2.1')->shouldBeCalled()->willReturn(New OidList(new Oid('1.3.6.1.2.1.1')));

        $this->getOid()->shouldBeLike(new Oid('1.3.6.1.2.1.1'));
    }
}
