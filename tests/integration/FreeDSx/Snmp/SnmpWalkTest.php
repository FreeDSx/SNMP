<?php

namespace integration\FreeDSx\Snmp;

use FreeDSx\Snmp\Oid;
use FreeDSx\Snmp\SnmpClient;

class SnmpWalkTest extends TestCase
{
    /**
     * @var SnmpClient
     */
    private $client;

    public function setUp(): void
    {
        parent::setUp();
        $this->client = $this->makeClient();
    }

    public function testItWalksAllOids()
    {
        $walk = $this->client->walk();

        while($walk->hasOids()) {
            $oid = $walk->next();

            $this->assertInstanceOf(
                Oid::class,
                $oid
            );
        }

        $this->assertGreaterThan(
            1,
            $walk->count()
        );
    }
}
