<?php

namespace integration\FreeDSx\Snmp;

use Exception;
use FreeDSx\Snmp\SnmpClient;
use Symfony\Component\Process\Process;

class TrapSinkTest extends TestCase
{
    /**
     * @var Process
     */
    private $subject;

    /**
     * @var SnmpClient
     */
    private $client;

    public function setUp(): void
    {
        parent::setUp();
        $this->client = $this->makeClient([
            'port' => 10162,
        ]);
        $this->subject = new Process([
            'php',
            __DIR__ . '/../../../bin/trapsink.php'
        ]);

        $this->subject->start();
        $this->waitForServerOutput('server starting...');
    }

    public function tearDown(): void
    {
        parent::tearDown();
        $this->subject->stop();
    }

    public function testTheTrapSinkReceivesV2Traps(): void
    {
        $this->client->sendTrap(
            123,
            '1.2.3.4.5'
        );
        $message = $this->waitForServerOutput('---received---');

        $this->assertStringContainsString(
            'Trap: 1.2.3.4.5',
            $message
        );
        $this->assertStringContainsString(
            'Version: 2',
            $message
        );
        $this->assertStringContainsString(
            'IP: 127.0.0.1',
            $message
        );
    }

    public function testTheTrapSinkReceivesV1Traps(): void
    {
        $this->client = $this->makeClient([
            'version' => 1,
            'port' => 10162,
        ]);
        $this->client->sendTrapV1(
            '1.2.3',
            '127.0.0.1',
            1,
            1,
            1
        );
        $message = $this->waitForServerOutput('---received---');

        $this->assertStringContainsString(
            'Trap: 1.2.3',
            $message
        );
        $this->assertStringContainsString(
            'Version: 1',
            $message
        );
        $this->assertStringContainsString(
            'IP: 127.0.0.1',
            $message
        );
    }

    /**
     * Informs from docker will not work. This is because when the trapsink responds, it realizes that the message came
     * from the same host (ie. 127.0.0.1) and tries to send it back the same way. ie. docker tries to send the inform
     * response to itself.
     *
     * The way to get it back to the host would be to use the special "host.docker.internal" DNS entry within the
     * container. But we cannot make these assumptions and cannot modify the address to send back to in the listener.
     */
    public function testTheTrapSinkReceivesInformsAndSendsResponse(): void
    {
        $this->markTestSkipped('Informs are not getting messages back here. See above for the detailed issue.');

        $response = $this->client->sendInform(
            123,
            '1.2.3.4.5.6'
        );
        $message = $this->waitForServerOutput('---received---');

        $this->assertNotNull($response);
        $this->assertStringContainsString(
            'Trap: 1.2.3.4.5.6',
            $message
        );
        $this->assertStringContainsString(
            'Version: 2',
            $message
        );
        $this->assertStringContainsString(
            'IP: 127.0.0.1',
            $message
        );
    }

    private function waitForServerOutput(string $marker): string
    {
        $maxWait = 10;
        $i = 0;

        while ($this->subject->isRunning()) {
            $output = $this->subject->getOutput();
            $this->subject->clearOutput();

            if (strpos($output, $marker) !== false) {
                return $output;
            }

            $i++;
            if ($i === $maxWait) {
                break;
            }

            sleep(1);
        }

        throw new Exception(sprintf(
            'The expected output was not received after %d seconds.',
            $i
        ));
    }
}
