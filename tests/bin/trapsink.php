<?php

use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Module\SecurityModel\Usm\UsmUser;
use FreeDSx\Snmp\Trap\TrapContext;
use FreeDSx\Snmp\Trap\TrapListenerInterface;
use FreeDSx\Snmp\TrapSink;

require __DIR__ . '/../../vendor/autoload.php';

$listener = new class implements TrapListenerInterface {
    public function accept(string $ip): bool
    {
        return true;
    }

    public function getUsmUser(
        EngineId $engineId,
        string $ipAddress,
        string $user
    ): ?UsmUser {
        return null;
    }

    public function receive(TrapContext $context): void
    {
        $trap = $context->getTrap();
        $version = $context->getVersion();
        $ip = $context->getIpAddress();

        echo "---received---, IP: $ip, Version: $version, Trap: {$trap->getTrapOid()->getValue()}";
    }
};

echo "server starting...";

$sink = new TrapSink($listener);
$sink->listen();
