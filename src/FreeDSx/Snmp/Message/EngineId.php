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

use FreeDSx\Snmp\Exception\UnexpectedValueException;

/**
 * Represents the SnmpEngineId and associated format.
 *
 * @see https://tools.ietf.org/html/rfc3411#section-5
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class EngineId
{
    /**
     * The Private Enterprise Number assigned to FreeDSx SNMP.
     *
     * @see https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
     */
    public const ENTERPRISE_NUMBER = 52564;

    public const FORMAT_IPV4 = 1;

    public const FORMAT_IPV6 = 2;

    public const FORMAT_MAC = 3;

    public const FORMAT_TEXT = 4;

    public const FORMAT_OCTET = 5;

    /**
     * @var string
     */
    protected static $octetDelim = ' ';

    /**
     * @var null|int
     */
    protected $format;

    /**
     * @var int
     */
    protected $enterpriseId;

    /**
     * @var string
     */
    protected $data;

    /**
     * @var null|string
     */
    protected $binary;

    public function __construct(string $data, ?int $format, int $enterpriseId = self::ENTERPRISE_NUMBER)
    {
        $this->data = $data;
        $this->format = $format;
        $this->enterpriseId = $enterpriseId;
    }

    /**
     * Get the decoded representation of the data based on the format.
     *
     * @return string
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * @return int
     */
    public function getEnterpriseId() : int
    {
        return $this->enterpriseId;
    }

    /**
     * @return null|int
     */
    public function getFormat() : ?int
    {
        return $this->format;
    }

    /**
     * @return bool
     */
    public function isVariableLengthFormat() : bool
    {
        return ($this->format !== null);
    }

    /**
     * @return string
     */
    public function toBinary()
    {
        if ($this->binary === null) {
            $enterpriseId = ($this->format !== null) ? ($this->enterpriseId | 0x80000000) : $this->enterpriseId;
            $enterpriseId = \hex2bin(\str_pad(\dechex($enterpriseId), 8, "0", STR_PAD_LEFT));

            if ($this->format !== null) {
                $this->binary = $enterpriseId.\chr($this->format).self::encodeDataFormat($this->format, $this->data);
            } else {
                $this->binary = $enterpriseId.\str_pad($this->data, 8, "\x00", STR_PAD_LEFT);
            }
        }

        return $this->binary;
    }

    /**
     * @return string
     */
    public function toHex() : string
    {
        return \bin2hex($this->toBinary());
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toHex();
    }

    /**
     * Construct the EngineID object based on a binary representation.
     */
    public static function fromBinary(string $engineId) : EngineId
    {
        return self::parse($engineId);
    }

    /**
     * Construct the EngineID object based on an IPv4 format.
     *
     * @param string $ipAddress
     * @param int $enterpriseNumber
     * @return EngineId
     */
    public static function fromIPv4(string $ipAddress, int $enterpriseNumber = self::ENTERPRISE_NUMBER) : EngineId
    {
        return new self($ipAddress, self::FORMAT_IPV4, $enterpriseNumber);
    }

    /**
     * Construct the EngineID object based on an IPv6 format.
     *
     * @param string $ipAddress
     * @param int $enterpriseNumber
     * @return EngineId
     */
    public static function fromIPv6(string $ipAddress, int $enterpriseNumber = self::ENTERPRISE_NUMBER) : EngineId
    {
        return new self($ipAddress, self::FORMAT_IPV6, $enterpriseNumber);
    }

    /**
     * Construct the EngineID object based on a MAC format.
     *
     * @param string $mac
     * @param int $enterpriseNumber
     * @return EngineId
     */
    public static function fromMAC(string $mac, int $enterpriseNumber = self::ENTERPRISE_NUMBER) : EngineId
    {
        return new self($mac, self::FORMAT_MAC, $enterpriseNumber);
    }

    /**
     * Construct the EngineID object based on a text format.
     *
     * @param string $text
     * @param int $enterpriseNumber
     * @return EngineId
     */
    public static function fromText(string $text, int $enterpriseNumber = self::ENTERPRISE_NUMBER) : EngineId
    {
        return new self($text, self::FORMAT_TEXT, $enterpriseNumber);
    }

    /**
     * Construct the EngineID object based on an octet format.
     *
     * @param string $octets
     * @param int $enterpriseNumber
     * @return EngineId
     */
    public static function fromOctet(string $octets, int $enterpriseNumber = self::ENTERPRISE_NUMBER) : EngineId
    {
        return new self($octets, self::FORMAT_OCTET, $enterpriseNumber);
    }

    /**
     * Construct an engineId using the RFC1910 method, which has no standardized format (just 8 bytes of data)
     *
     * @param string $data
     * @param int $enterpriseNumber
     * @return EngineId
     */
    public static function fromRFC1910($data, int $enterpriseNumber = self::ENTERPRISE_NUMBER) : EngineId
    {
        return new self($data, null, $enterpriseNumber);
    }

    protected static function parse(string $engineId) : EngineId
    {
        $length = \strlen($engineId);
        # The engine ID must be between 5 and 32 bytes long
        if ($length < 5 || $length > 32) {
            throw new UnexpectedValueException('The engine ID length is invalid.');
        }
        # It cannot be composed of all H'00' or H'FF'
        if (\str_repeat("\x00", $length) === $engineId || \str_repeat("\xff", $length) === $engineId) {
            throw new UnexpectedValueException('The engine ID is malformed.');
        }
        $format = null;
        $enterpriseId = \hexdec(\bin2hex(\substr($engineId, 0, 4)));

        # The first bit specifies whether it is variable length format from RFC3411...
        if (\ord($engineId[0]) >= 128) {
            $format = \ord($engineId[4]);
            # The first bit of the ID is an identifier for variable length format, so flip it.
            $enterpriseId ^= 0x80000000;
            $data = self::parseDataFormat($format, \substr($engineId, 5));
        } else {
            $data = \substr($engineId, 4);
        }

        return new self($data, $format, $enterpriseId);
    }

    /**
     * @return mixed
     */
    protected static function parseDataFormat(int $format, string $data)
    {
        if ($format === self::FORMAT_IPV4) {
            $data = self::parseIPv4($data);
        } elseif ($format === self::FORMAT_IPV6) {
            $data = self::parseIPv6($data);
        } elseif ($format === self::FORMAT_MAC) {
            $data = self::parseMAC($data);
        } elseif ($format === self::FORMAT_TEXT) {
            $data = $data;
        } elseif ($format === self::FORMAT_OCTET) {
            $data = \bin2hex($data);
        }

        return $data;
    }

    /**
     * @return bool|string
     */
    protected static function encodeDataFormat(int $format, string $data)
    {
        if ($format === self::FORMAT_IPV4) {
            $data = self::encodeIPv4($data);
        } elseif ($format === self::FORMAT_IPV6) {
            $data = self::encodeIPv6($data);
        } elseif ($format === self::FORMAT_MAC) {
            $data = self::encodeMAC($data);
        } elseif ($format === self::FORMAT_OCTET) {
            $data = self::encodeOctets($data);
        }

        return $data;
    }

    /**
     * @param string $data
     * @return string
     */
    protected static function encodeOctets($data)
    {
        if (\strpos($data, self::$octetDelim) !== false) {
            $data = \explode(self::$octetDelim, $data);
            foreach ($data as $i => $piece) {
                $data[$i] = \str_pad($piece, 2, '0', STR_PAD_LEFT);
            }
            $data = \implode('', $data);
        }
        if (!\ctype_xdigit($data)) {
            throw new UnexpectedValueException('The octets contains invalid values.');
        }
        if (\strlen($data) % 2) {
            throw new UnexpectedValueException('The octets must be an even length.');
        }

        return \hex2bin($data);
    }

    protected static function parseIPv4(string $data) : string
    {
        $length = \strlen($data);
        if ($length !== 4) {
            throw new UnexpectedValueException(sprintf('Expected 4 bytes for IPv4, got %s.', $length));
        }

        $ipAddress = [];
        for ($i = 0; $i < 4; $i++) {
            $ipAddress[] = \ord($data[$i]);
        }

        return \implode('.', $ipAddress);
    }

    /**
     * @param string $data
     * @return string
     */
    protected static function encodeIPv4(string $data)
    {
        if (!\filter_var($data, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new UnexpectedValueException(sprintf('The IPv4 address is invalid: %s', $data));
        }
        $pieces = \explode('.', $data);

        $encoded = '';
        foreach ($pieces as $piece) {
            $encoded .= \chr((int) $piece);
        }

        return $encoded;
    }

    protected static function parseIPv6(string $data) : string
    {
        $length = \strlen($data);
        if ($length !== 12) {
            throw new UnexpectedValueException(sprintf('Expected 12 bytes for IPv6, got %s.', $length));
        }

        $pieces = \str_split($data, 2);
        foreach ($pieces as $i => $piece) {
            $pieces[$i] = \ltrim(\bin2hex($piece), '0');
        }

        return \implode(':', $pieces);
    }

    /**
     * @param string $data
     * @return string
     */
    protected static function encodeIPv6(string $data)
    {
        if (!\filter_var($data, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            throw new UnexpectedValueException(sprintf('The IPv6 address is invalid: %s', $data));
        }
        $pieces = \explode(':', $data);

        $encoded = '';
        foreach ($pieces as $piece) {
            $piece = \str_pad($piece, 4, '0', STR_PAD_LEFT);
            $encoded .= \hex2bin($piece);
        }

        return $encoded;
    }

    protected static function parseMAC(string $data) : string
    {
        $length = \strlen($data);
        if ($length !== 6) {
            throw new UnexpectedValueException(sprintf('Expected 6 bytes for a MAC, got %s.', $length));
        }

        return \implode(':', \str_split(\bin2hex($data), 2));
    }

    /**
     * @param string $data
     * @return string
     */
    protected static function encodeMAC(string $data)
    {
        if (!\filter_var($data, FILTER_VALIDATE_MAC)) {
            throw new UnexpectedValueException(sprintf('The MAC is invalid: %s', $data));
        }
        $pieces = \explode(':', $data);

        foreach ($pieces as $i => $piece) {
            $pieces[$i] = \str_pad($piece, '2', '0', STR_PAD_LEFT);
        }

        return \hex2bin(\implode('', $pieces));
    }
}
