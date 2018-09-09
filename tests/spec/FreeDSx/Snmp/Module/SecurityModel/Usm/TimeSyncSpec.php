<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Module\SecurityModel\Usm;

use FreeDSx\Snmp\Module\SecurityModel\Usm\TimeSync;
use PhpSpec\ObjectBehavior;

class TimeSyncSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(1, 2);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(TimeSync::class);
    }

    function it_should_get_the_boot_time()
    {
        $this->getEngineBoot()->shouldBeEqualTo(1);
    }

    function it_should_get_the_engine_time()
    {
        $this->getEngineTime()->shouldBeEqualTo(2);
    }

    function it_should_get_when_the_time_was_synced()
    {
        $this->getWhenSynced()->shouldBeAnInstanceOf(\DateTime::class);
    }
}
