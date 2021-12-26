<?php

namespace integration\FreeDSx\Snmp;

use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\SnmpClient;

class SnmpClientTest extends TestCase
{
    /**
     * @var SnmpClient
     */
    private $subject;

    public function setUp(): void
    {
        parent::setUp();
        $this->subject = $this->makeReadOnlyClient();
    }

    public function testGetReturnsOidListWithValue(): void
    {
        $value = $this->subject->get('1.3.6.1.2.1.1.1.0');

        $this->assertCount(1, $value);
        $this->assertStringContainsStringIgnoringCase(
            'Linux',
            (string)$value->first()->getValue()
        );
    }

    public function testGetValueReturnsSingleOidValue(): void
    {
        $value = $this->subject->getValue('1.3.6.1.2.1.1.1.0');

        $this->assertIsString($value);
        $this->assertStringContainsStringIgnoringCase(
            'Linux',
            $value
        );
    }

    public function testGetOidReturnsSingleOid(): void
    {
        $oid = $this->subject->getOid('1.3.6.1.2.1.1.1.0');

        $this->assertInstanceOf(
            Oid::class,
            $oid
        );
        $this->assertStringContainsStringIgnoringCase(
            'Linux',
            $oid->getValue()
        );
    }
}
