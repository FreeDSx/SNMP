<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Protocol;

use FreeDSx\Asn1\Encoder\BerEncoder;
use FreeDSx\Asn1\Type\AbstractType;

/**
 * Specifies SNMP specific BER encoding rules defined in RFC 3417, Section 8:
 *
 *    (1)   When encoding the length field, only the definite form is used;
 *          use of the indefinite form encoding is prohibited.  Note that
 *          when using the definite-long form, it is permissible to use
 *          more than the minimum number of length octets necessary to
 *          encode the length field.
 *
 *    (2)   When encoding the value field, the primitive form shall be used
 *          for all simple types, i.e., INTEGER, OCTET STRING, and OBJECT
 *          IDENTIFIER (either IMPLICIT or explicit).  The constructed form
 *          of encoding shall be used only for structured types, i.e., a
 *          SEQUENCE or an IMPLICIT SEQUENCE.
 *
 *    (3)   When encoding an object whose syntax is described using the
 *          BITS construct, the value is encoded as an OCTET STRING, in
 *          which all the named bits in (the definition of) the bitstring,
 *          commencing with the first bit and proceeding to the last bit,
 *          are placed in bits 8 (high order bit) to 1 (low order bit) of
 *          the first octet, followed by bits 8 to 1 of each subsequent
 *          octet in turn, followed by as many bits as are needed of the
 *          final subsequent octet, commencing with bit 8.  Remaining bits,
 *          if any, of the final octet are set to zero on generation and
 *          ignored on receipt.
 *
 * @see https://tools.ietf.org/html/rfc3417#section-8
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SnmpEncoder extends BerEncoder
{
    public function __construct(array $options = [])
    {
        parent::__construct([
            'primitive_only' => [
                AbstractType::TAG_TYPE_OCTET_STRING,
            ],
        ]);
    }
}
