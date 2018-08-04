# FreeDSx SNMP [![Build Status](https://travis-ci.org/FreeDSx/SNMP.svg?branch=master)](https://travis-ci.org/FreeDSx/SNMP) [![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/freedsx/snmp?branch=master&svg=true)](https://ci.appveyor.com/project/ChadSikorra/snmp)
FreeDSx SNMP is a pure PHP SNMP library. It has no requirement on the core PHP SNMP extension. It implements SNMP
client functionality described in [RFC 3412](https://tools.ietf.org/html/rfc3412) / [RFC 3416](https://tools.ietf.org/html/rfc3416) / [RFC 3414](https://tools.ietf.org/html/rfc3414).
It also includes functionality described in various other RFCs, such as SHA2 authentication ([RFC 7860](https://tools.ietf.org/html/rfc7860)) and strong encryption
mechanisms ([3DES](https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00) / [AES-192-256](https://tools.ietf.org/html/draft-blumenthal-aes-usm-04)).
Some main features include:

* SNMP version 1, 2, and 3 support.
* Supports all authentication mechanisms (md5, sha1, sha224, sha256, sha384, sha512).
* Supports all privacy encryption mechanisms (des, 3des, aes128, aes192, aes256).
* Supports all client request types (get, get next, bulk, set, inform, trapV1, trapV2).
* Supports sending SNMPv1 and SNMPv2 traps (including inform requests).

The OpenSSL extension is required for privacy / encryption support.

# Documentation

* [SNMP Client](/docs/Client)
  * [Configuration](/docs/Client/Configuration.md)
  * [General Usage](/docs/Client/General-Usage.md)
  * [Request Types](/docs/Client/Request-Types.md)

# Getting Started

Install via composer:

```bash
composer require freedsx/snmp
```

Use the SnmpClient class and the helper classes:

```php
use FreeDSx\Snmp\SnmpClient;

$snmp = new SnmpClient([
    'host' => 'servername',
    'version' => 2,
    'community' => 'secret',
]);

# Get a specific OID value as a string...
echo $snmp->getValue('1.3.6.1.2.1').PHP_EOL;

# Get a specific OID as an object...
$oid = $snmp->getOid('1.3.6.1.2.1');
var_dump($oid);

echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()).PHP_EOL;

# Get multiple OIDs and iterate through them as needed...
$oids = $snmp->get('1.3.6.1.2.1.1.1', '1.3.6.1.2.1.1.3', '1.3.6.1.2.1.1.5');
 
foreach($oids as $oid) {
    echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()).PHP_EOL;
}

```

For a complete configuration reference please see the [configuration doc](/docs/Client/Configuration.md). There are also
SNMP v3 examples for [NoAuthNoPriv](/docs/Client/General-Usage.md#NoAuthNoPriv), [AuthNoPriv](/docs/Client/General-Usage.md#AuthNoPriv), and [AuthPriv](/docs/Client/General-Usage.md#AuthPriv)
in the [general usage doc](/docs/Client/General-Usage.md).
