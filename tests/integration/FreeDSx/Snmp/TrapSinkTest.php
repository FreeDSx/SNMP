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
            'port' => 162,
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

    public function testTheTrapSinkWorks(): void
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
            $maxWait
        ));
    }
}
