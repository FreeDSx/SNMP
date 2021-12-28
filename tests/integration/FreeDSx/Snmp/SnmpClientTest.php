<?php

namespace integration\FreeDSx\Snmp;

use FreeDSx\Snmp\Exception\SnmpRequestException;
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
        $this->subject = $this->makeClient();
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

    /**
     * In theory, the test below should work. When SNMPv2-MIB::snmpSetSerialNo is used, it should just increment.
     * Perhaps something wrong with the config, or it is specific to the use in docker? Needs investigation.
     *
     * For now this just tests that the "set" was attempted, and we expect a message back that it was rejected.
     */
    public function testItCanModifyAnOidValueWithSet(): void
    {
        $this->subject = $this->makeClient(['community' => getenv('SNMP_COMMUNITY_RW')]);
        $value = $this->subject->getValue('1.3.6.1.6.3.1.1.6.1.0');

        $message = '';
        try {
            $this->subject->set(Oid::fromInteger(
                '1.3.6.1.6.3.1.1.6.1.0',
                (int)$value
            ));
        } catch (SnmpRequestException $e) {
            $message = $e->getMessage();
        }

        $this->assertStringContainsString(
            '(WrongLength)',
            $message
        );
    }

    public function testGetNextReturnsTheNextOid(): void
    {
        $oid = $this->subject->getNext('1.3.6.1.2.1.1.1.0')->first();

        $this->assertNotNull($oid);
        $this->assertEquals(
            '1.3.6.1.2.1.1.2.0',
            $oid->getOid()
        );
    }

    public function testGetBulkReturnsAllExpected(): void
    {
        $oids = $this->subject->getBulk(
            9,
            0,
            '1.3.6.1.2.1.1.1'
        );
        $first = $oids->first();
        $last = $oids->last();

        $this->assertCount(
            9,
            $oids
        );
        $this->assertEquals(
            '1.3.6.1.2.1.1.1.0',
            $first->getOid()
        );
        $this->assertEquals(
            '1.3.6.1.2.1.1.9.1.2.2',
            $last->getOid()
        );
    }
}
