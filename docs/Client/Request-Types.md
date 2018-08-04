Client Requests
================

The client can send any SNMP request through various request objects. These also exist as convenience methods on the
client itself. These examples assume `$snmp` is an instance of the `SnmpClient`.

* [Get](#get)
* [GetNext](#getnext)
* [GetBulk](#getbulk)
* [Set](#set)
* [Trap V1](#trap-v1)
* [Trap V2](#trap-v2)
* [Inform](#inform)

## Get

Get a list of specified OIDs:

```php
use FreeDSx\Snmp\Exception\SnmpRequestException;

try {
    $oids = $snmp->get('1.3.6.1.2.1.1.1', '1.3.6.1.2.1.1.3', '1.3.6.1.2.1.1.5');
} catch (SnmpRequestException $e) {
    echo $e->getMessage();
    exit;
}

# Get the total returned count:
echo "OID Count: ".count($oids).PHP_EOL;

# Get the first OID in the list:
echo "First: ".$oids->first().PHP_EOL;

# Get the last OID in the list:
echo "Last: ".$oids->last().PHP_EOL;

# Get a specific OID in the list, obtain its value:
echo $oids->get('1.3.6.1.2.1.1.1')->getValue().PHP_EOL;

# Iterate through them all:
foreach($oids as $oid) {
    echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()).PHP_EOL;
}
```

Get a single OID object:

```php
use FreeDSx\Snmp\Exception\SnmpRequestException;

try {
    $oid = $snmp->getOid('1.3.6.1.2.1.1.1');
} catch (SnmpRequestException $e) {
    echo $e->getMessage();
    exit;
}

echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()).PHP_EOL;
```

Get the value (as a string) of a single OID object:

```php
use FreeDSx\Snmp\Exception\SnmpRequestException;

try {
    echo $snmp->getValue('1.3.6.1.2.1.1.1').PHP_EOL;
} catch (SnmpRequestException $e) {
    echo $e->getMessage();
    exit;
}
```

## GetNext

Get the next MIB variable in the tree back:

```php
use FreeDSx\Snmp\Exception\SnmpRequestException;

try {
    $oid = $snmp->getNext('1.3.6.1.2.1.1.5.0');
} catch (SnmpRequestException $e) {
    echo $e->getMessage();
    exit;
}

echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()).PHP_EOL;
```

## GetBulk

Get bulk provides an efficient way for retrieving multiple OID variables at a time instead of issuing several get next
requests. To send a a GetBulk request you must specify two parameters:

* **Max-Repetitions**: The max number of variables to return for all the repeating OIDs.
* **Non-Repeaters**: The number of variables in the variable list for which a GetNext request must be done.

```php
use FreeDSx\Snmp\Exception\SnmpRequestException;

try {
    # The first argument specifies the max repetitions, the second is the non-repeaters.
    $oids = $snmp->getBulk(5, 1, '1.3.6.1.2.1.2.2');
} catch (SnmpRequestException $e) {
    echo $e->getMessage();
    exit;
}

# Iterate through the results:
foreach($oids as $oid) {
    echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()).PHP_EOL;
}
```

## Set

Set an OID to a specific value. You can use the various `Oid::from*()` factory methods to construct the OID value needed:

```php
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Oid;

try {
    # Set the contact OID string...
    $snmp->set(Oid::fromString('1.3.6.1.2.1.1.4.0', 'Chad.Sikorra@gmail.com'));
} catch (SnmpRequestException $e) {
    echo $e->getMessage();
    exit;
}
```

## Trap V1

Send an SNMP v1 Trap to a remote host. To do this you should construct the client using port 162 and SNMP version 1:

```php
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\SnmpClient;
use FreeDSx\Snmp\Exception\SnmpRequestException;

# Construct the SNMP client with an array of options...
$snmp = new SnmpClient([
   # Specify the remote host name (defaults to "localhost")
   'host' => 'testserver',
   # Specify the community name to use (defaults to "public")
   'community' => 'foo',
   # Specify the version (defaults to "2").
   'version' => 1,
   # Use the SNMP trap port
   'port' => 162,
]);

try {
    # The parameters are:
    #     1. The enterprise OID to trigger
    #     2. The IP address.
    #     3. The generic trap type
    #     4. The specific trap type
    #     5. The system uptime (in seconds)
    #     6. The OIDs and their values
    $snmp->sendTrapV1(
        '1.3.6.1.4.1.2021.251.1',
         $_SERVER['SERVER_ADDR'],
         TrapV1Request::GENERIC_COLD_START,
         0,
         60,
         Oid::fromTimeticks('1.3.6.1.2.1.1.3', 60)
    );
} catch (SnmpRequestException $e) {
    echo sprintf('Unable to send trap: %s', $e->getMessage());
    exit;
}
```

## Trap V2

Send an SNMP v2 type Trap to a remote host. To do this you should construct the client using port 162 and SNMP version
2 or 3:

```php
use FreeDSx\Snmp\SnmpClient;
use FreeDSx\Snmp\Exception\SnmpRequestException;

# Construct the SNMP client with an array of options...
$snmp = new SnmpClient([
   # Specify the remote host name (defaults to "localhost")
   'host' => 'testserver',
   # Specify the community name to use (defaults to "public")
   'community' => 'foo',
   # Specify the version (defaults to "2").
   'version' => 2,
   # Use the SNMP trap port
   'port' => 162,
]);

try {
    # The parameters are:
    #     1. The system uptime (in seconds)
    #     2. The trap OID
    #     3. The OIDs and their values
    $snmp->sendTrap(
        60,
        '1.3.6.1.4.1.2021.251.1', 
         Oid::fromTimeticks('1.3.6.1.2.1.1.3', 60)
    );
} catch (SnmpRequestException $e) {
    echo sprintf('Unable to send trap: %s', $e->getMessage());
    exit;
}
```

## Inform

Send an inform request to a remote host. This is identical to a SNMP v2 trap, only it requires a response from the host.
To do this you should construct the client using port 162 and SNMP version 2 or 3:

```php
use FreeDSx\Snmp\SnmpClient;
use FreeDSx\Snmp\Exception\SnmpRequestException;

# Construct the SNMP client with an array of options...
$snmp = new SnmpClient([
   # Specify the remote host name (defaults to "localhost")
   'host' => 'testserver',
   # Specify the community name to use (defaults to "public")
   'community' => 'foo',
   # Specify the version (defaults to "2").
   'version' => 2,
   # Use the SNMP trap port
   'port' => 162,
]);

try {
    # The parameters are:
    #     1. The system uptime (in seconds)
    #     2. The trap OID
    #     3. The OIDs and their values
    $snmp->sendInform(
        60,
        '1.3.6.1.4.1.2021.251.1', 
         Oid::fromTimeticks('1.3.6.1.2.1.1.3', 60)
    );
} catch (SnmpRequestException $e) {
    echo sprintf('Unable to send inform: %s', $e->getMessage());
    exit;
}
```
