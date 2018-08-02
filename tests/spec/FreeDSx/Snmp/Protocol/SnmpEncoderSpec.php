<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Protocol;

use FreeDSx\Asn1\Encoder\BerEncoder;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Snmp\Protocol\SnmpEncoder;
use PhpSpec\ObjectBehavior;

class SnmpEncoderSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(SnmpEncoder::class);
    }

    function it_should_be_an_instance_of_a_ber_encoder()
    {
        $this->shouldBeAnInstanceOf(BerEncoder::class);
    }

    function it_should_only_allow_octet_strings_as_primitives()
    {
        $this->getOptions()->shouldNotHaveKeyWithValue('primitive_only',AbstractType::TAG_TYPE_OCTET_STRING);
    }
}
