SNMP Walk
================

The SNMP client can perform an SNMP walk by using the helper class when calling the `walk()` method. The helper class
has several methods to help control various aspects of the walk.

* [Basic Use](#basic-use)
* [API](#api)
  * [getOid](#getoid)
  * [next](#next)
  * [skipTo](#skipto)
  * [restart](#restart)
  * [startAt](#startat)
  * [endAt](#endat)
  * [count](#count)
  * [isComplete](#iscomplete)
  * [hasOids](#hasoids)
  * [subtreeOnly](#subtreeonlybool-subtreeonly--true)
  * [maxRepetitions](#maxrepetitionsint-maxrepetitions)
  * [useGetBulk](#usegetbulkbool-usegetbulk)

## Basic Use

You can perform a basic walk using the following example. By default the walk will start at OID `1.3.6.1.2.1`. and will
go until the end of the subtree. You can control this behavior by passing a `$startAt` and `$endAt` parameter to walk
(respectively). If you would like to walk until the end of the MIB view, instead of the subtree, you can pass use the
method `subtreeOnly(false)` of the walk class.

```php
# Using the SnmpClient, get the helper class for the walk...
$walk = $snmp->walk();

# Specify to walk past the end of the subtree if desired
# $walk->subtreeOnly(false);

# Keep the walk going until there are no more OIDs left
while($walk->hasOids()) {
    try {
        # Get the next OID in the walk
        $oid = $walk->next();
        echo sprintf("%s = %s", $oid->getOid(), $oid->getValue()).PHP_EOL;
    } catch (\Exception $e) {
        # If we had an issue, display it here (network timeout, etc)
        echo "Unable to retrieve OID. ".$e->getMessage().PHP_EOL;
    }
}

echo sprintf("Walked a total of %s OIDs.", $walk->count()).PHP_EOL; 
```

By default the client will send a getBulk request if you are using SNMP v2/v3, which improves performance.

## API

### getOid

An alias of `next()` for getting the next OID in the walk.

```php
$oid = $walk->getOid();
echo sprintf("%s = %s", $oid->getOid(), $oid->getValue()).PHP_EOL;
```

### next

Get the next OID in the walk.

```php
$oid = $walk->next();
echo sprintf("%s = %s", $oid->getOid(), $oid->getValue()).PHP_EOL;
```

### skipTo

Skip to the OID specified. The following call to `next()` will be called for this OID.

```php
# Get the next OID as normal..
$oid = $walk->next();
var_dump($oid);

# This will make the next be OID 1.3.6.1.2.1.1.9.1.2.7 (ie. the "next" in the sequence)
$oid = $walk->skipTo('1.3.6.1.2.1.1.9.1.2.6')
var_dump($oid);
```

### restart

Regardless of where you are in the walk, start back at the default OID (also resets the count).

```php
# Restart the walk, starting it over again...
$walk->restart();

# This will be the starting OID and a count of 1
$oid = $walk->next();
var_dump($oid);
var_dump($walk->count());
```

### startAt

Start the walk at a specific OID instead of the default (`1.3.6.1.2.1`). This can also be done when constructing the
walk.

```php
# Using the constructor from the SNMP client (the first parameter is for where to start)..
$walk = $snmp->walk('1.3.6.1.2.1.1.8');

# Using the method after construction from the SnmpClient..
$walk = $snmp->walk()->startAt('1.3.6.1.2.1.1.8');
```

### endAt

End the walk at a specific OID instead, whether or not it is the end of the MIB view. This can also be done when
constructing the walk.

```php
# Using the method after construction from the SnmpClient..
$walk = $snmp->walk()->endAt('1.3.6.1.2.1.1.8');

# Using the constructor from the SNMP client (the second parameter is for where to end)..
$walk = $snmp->walk(null, '1.3.6.1.2.1.1.8');
```

### count

Get the number of OIDs processed by the walk. This is reset when the `restart()` method is called.

```php
# Walk a couple OIDs...
$walk->next();
$walk->next();
$walk->next();

# Check the count..
var_dump($walk->count());
```

### isComplete

Returns a boolean for whether or not the walk is complete. This will be true if we are at the ending OID that was specified
explicitly or an OID was reached that has an end of MIB view status.

```php
while (!$walk->isComplete()) {
    $oid = $walk->next();
}
```

### hasOids

The inverse of `isComplete()`. It will return true if there are still OIDs to be returned in the walk.

```php
while ($walk->hasOids()) {
    $oid = $walk->next();
}
```

### subtreeOnly(bool $subtreeOnly = true)

Whether or not to walk only the subtree specified by the starting OID. The default is to only walk the subtree.

```php
# Walk past the subtree...
$walk->subtreeOnly(false);
```

###  maxRepetitions(int $maxRepetitions)

Specifies the maximum amount of OIDs to attempt to retrieve at a time during a getBulk request (SNMP v2/v3) during the
walk. This defaults to 100. You may have to modify this depending on device behavior. The larger this is set, the faster
the walk will likely complete.

**Note**: Per SNMP RFCs, devices are only supposed to return the max amount of OIDs that can fit within a UDP packet,
regardless of how high this is set. However, not all devices seem to behave this way and may have specific maximums for
this value. If you notice issues, setting this lower may help.

```php
# Walk past the subtree...
$walk->maxRepetitions(10);
```

### useGetBulk(bool $useGetBulk)

Specifies whether a getBulk request should be sent for the walk. By default it will send using a getBulk request if you
are using SNMP v2/v3.

```php
# Explicitly disable getBulk requests if you want...
$walk->useGetBulk(false);
```
