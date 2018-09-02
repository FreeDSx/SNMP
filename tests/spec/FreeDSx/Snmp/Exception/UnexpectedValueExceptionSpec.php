<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Exception;

use FreeDSx\Snmp\Exception\UnexpectedValueException;
use PhpSpec\ObjectBehavior;

class UnexpectedValueExceptionSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(UnexpectedValueException::class);
    }

    function it_should_extend_UnexpectedValueException()
    {
        $this->shouldBeAnInstanceOf(\UnexpectedValueException::class);
    }
}
