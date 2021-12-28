<?php

use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Module\SecurityModel\Usm\UsmUser;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
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

        if ($trap instanceof TrapV2Request) {
            echo "---received---, IP: $ip, Version: $version, Trap: {$trap->getTrapOid()->getValue()}";
        } elseif ($trap instanceof TrapV1Request) {
            echo "---received---, IP: $ip, Version: $version, Trap: {$trap->getEnterprise()}";
        }
    }
};

echo "server starting...";

$sink = new TrapSink(
    $listener,
    [
        'port' => 10162,
    ]
);
$sink->listen();
