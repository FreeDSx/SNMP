<?php

namespace integration\FreeDSx\Snmp;

use FreeDSx\Snmp\SnmpClient;
use PHPUnit\Framework\TestCase as BaseTestCase;

class TestCase extends BaseTestCase
{
    public function makeClient(array $options = []): SnmpClient
    {
        return new SnmpClient(array_merge(
            $this->defaultOptions(),
            $options
        ));
    }

    private function defaultOptions(): array
    {
        return [
            'version' => 2,
            'community' => getenv('SNMP_COMMUNITY_RO'),
            'user' => getenv('SNMP_USER'),
            'use_auth' => true,
            'auth_pwd' => getenv('SNMP_PASS_USER'),
            'auth_mech' => 'md5',
            'use_priv' => false,
            'priv_mech' => 'des',
            'priv_pwd' => getenv('SNMP_PASS_PRIV'),
            'host' => getenv('SNMP_SERVER'),
            'port' => (int) getenv('SNMP_PORT'),
        ];
    }
}
