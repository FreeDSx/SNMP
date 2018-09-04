SNMP Client Configuration
================

* [General Options](#general-options)
    * [host](#host)
    * [port](#port)
    * [version](#version)
    * [community](#community)
    * [user](#user)
    * [use_auth](#use_auth)
    * [auth_pwd](#auth_pwd)
    * [auth_mech](#auth_mech)
    * [use_priv](#use_priv)
    * [priv_mech](#priv_mech)
    * [priv_pwd](#priv_pwd)
    * [engine_id](#engine_id)
    * [context_name](#context_name)
    * [timeout_connect](#timeout_connect)
    * [timeout_read](#timeout_read)

The SNMP client is configured through an array of configuration values. The configuration is simply passed to the client
on construction:

```php
use FreeDSx\Snmp\SnmpClient;

$snmp = new SnmpClient([
    'host' => 'server',
    'version' => 2,
    'community' => 'foo',
]);
```

The following documents these various configuration options and how they impact the client.

## General Options

------------------
#### host

The host to connect to.

**Default**: `localhost`

------------------
#### port

The port to connect to on the SNMP host.

**Default**: `161`

------------------
#### version

The SNMP version to use. Must be one of: 1, 2, 3

**Default**: `2`

------------------
#### community

The community name to use when sending SNMP version 1 or 2 communications.

**Default**: `public`

------------------
#### user

The user to connect to when using SNMP version 3.

**Default**: `(null)`

------------------
#### use_auth

Whether or not to use authentication for the specified user when using SNMP version 3.

**Default**: `false`

------------------
#### auth_pwd

The authentication password to use for the specified user when using SNMP version 3.

**Default**: `(null)`

------------------
#### auth_mech

The authentication mechanism to use for the specified user when using SNMP version 3. Available options are:

* md5
* sha1
* sha224
* sha256
* sha384
* sha512

**Default**: `(null)`

------------------
#### use_priv

Whether or not to use privacy (encryption) for the specified user when using SNMP version 3.

**Default**: `false`

------------------
#### priv_pwd

The privacy password to use for the specified user when using SNMP version 3.

**Default**: `(null)`

------------------
#### priv_mech

The privacy mechanism to use for the specified user when using SNMP version 3. Available options are:

* des
* aes128
* 3des
* aes192
* aes256
* aes192blu
* aes256blu

By default the `aes192` and `aes256` mechanisms use the "Reeder" key localization strategy. This strategy
will work for Cisco devices. If it doesn't work you may want to try the `aes192blu` or `aes256blu` mechanisms,
which uses the "Blumenthal" key localization strategy. Unfortunately the AES192 / AES256 / 3DES mechanisms were never
officially standardized and multiple implementations exist.

**Default**: `(null)`

------------------
#### engine_id

The engine id of the remote SNMP host. If you specify it here, this will always be used. If you leave it empty, then the
engine id will be discovered automatically as part of the SNMP version 3 USM discovery process.

If you define this it must be an instance of `FreeDSx\Snmp\Message\EngineId`.

**Default**: `(null)`

------------------
#### context_name

The context name to use when communicating with the remote SNMP host.

**Default**: `(null)`

------------------
#### timeout_connect

The timeout period (in seconds) when connecting to an SNMP host.

**Default**: `3`

------------------
#### timeout_read

The timeout period (in seconds) when reading data from an SNMP host.

**Default**: `10`
