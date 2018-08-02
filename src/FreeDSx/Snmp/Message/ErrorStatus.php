<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Message;

/**
 * Possible error status values. RFC 3416 Section 3.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ErrorStatus
{
    public const NO_ERROR = 0;

    public const TOO_BIG = 1;

    public const NO_SUCH_NAME = 2;

    public const BAD_VALUE = 3;

    public const READ_ONLY = 4;

    public const GEN_ERROR = 5;

    public const NO_ACCESS = 6;

    public const WRONG_TYPE = 7;

    public const WRONG_LENGTH = 8;

    public const WRONG_ENCODING = 9;

    public const WRONG_VALUE = 10;

    public const NO_CREATION = 11;

    public const INCONSISTENT_VALUE = 12;

    public const RESOURCE_UNAVAILABLE = 13;

    public const COMMIT_FAILED = 14;

    public const UNDO_FAILED = 15;

    public const AUTHORIZATION_ERROR = 16;

    public const NOT_WRITABLE = 17;

    public const INCONSISTENT_NAME = 18;
}
