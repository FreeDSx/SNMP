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

use FreeDSx\Snmp\Exception\RediscoveryNeededException;
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Message\ScopedPduResponse;
use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\OidList;
use FreeDSx\Snmp\Response\ReportResponse;
use PhpSpec\ObjectBehavior;

class RediscoveryNeededExceptionSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new MessageResponseV3(
            new MessageHeader(1),
            new ScopedPduResponse(new ReportResponse(1, 2, 1, new OidList(new Oid('1.2.3'))))
        ));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(RediscoveryNeededException::class);
    }

    function it_should_be_an_instance_of_snmp_request_exception()
    {
        $this->shouldBeAnInstanceOf(SnmpRequestException::class);
    }
}
