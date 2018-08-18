General SNMP Client Usage
===================

* [SNMP v1 and v2](#snmp-v1-and-v2)
* [SNMP v3](#snmp-v3)
  * [NoAuthNoPriv](#noauthnopriv)
  * [AuthNoPriv](#authnopriv)
  * [AuthPriv](#authpriv)
* [Requests and Responses](#requests-and-responses)

The SnmpClient class is your main point for sending SNMP requests and receiving responses from the host. This details
some general information on using the class to send SNMP v1/v2/v3 requests and get responses back.

## SNMP v1 and v2

When connecting via SNMP v1/v2 you only need to provide the host name and a community string:

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
   'version' => 1,
]);

# Perform a simple get request to return the value as a string
try {
   echo $snmp->getValue('1.3.6.1.2.1').PHP_EOL;
} catch (SnmpRequestException $e) {
  echo $e->getMessage().PHP_EOL;
}
```

## SNMP v3

When connecting via SNMP v3 you need to specify a host name, a user, and whether or not authentication / privacy is
needed, along with the mechanisms needed for both.


### NoAuthNoPriv

An example with a user that has no authentication / privacy requirements (NoAuthNoPriv):

```php
use FreeDSx\Snmp\SnmpClient;

# Construct the SNMP client for a user with no auth or privacy
$snmp = new SnmpClient([
   # Specify the remote host name (defaults to "localhost")
   'host' => 'testserver',
   # Specify the version (defaults to "2").
   'version' => 3,
   # The SNMP user to connect with
   'user' => 'johndoe',
]);
```

### AuthNoPriv

An example with a user only requiring authentication (AuthNoPriv):

```php
use FreeDSx\Snmp\SnmpClient;

# Construct the SNMP client for a user requiring auth
$snmp = new SnmpClient([
   # Specify the remote host name (defaults to "localhost")
   'host' => 'testserver',
   # Specify the version (defaults to "2").
   'version' => 3,
   # The SNMP user to connect with
   'user' => 'johndoe',
   # Specify to use authentication
   'use_auth' => true,
   # Specify the authentication mechanism for the user
   'auth_mech' => 'sha1',
   # Specify the user's password
   'auth_pwd' => "P@ssword123",
]);
```

### AuthPriv

An example with a user requiring both authentication and privacy (AuthPriv):

```php
use FreeDSx\Snmp\SnmpClient;

# Construct the SNMP client for a user requiring auth / privacy
$snmp = new SnmpClient([
   # Specify the remote host name (defaults to "localhost")
   'host' => 'testserver',
   # Specify the version (defaults to "2").
   'version' => 3,
   # The SNMP user to connect with
   'user' => 'johndoe',
   # Specify to use authentication
   'use_auth' => true,
   # Specify the authentication mechanism for the user
   'auth_mech' => 'sha1',
   # Specify the user's password
   'auth_pwd' => "P@ssword123",
   # Specify to use privacy
   'use_priv' => true,
   # Specify the privacy mechanism for the user
   'priv_mech' => 'aes128',
   # Specify the privacy password for the user (different from the authentication password)
   'priv_pwd' => 'Secret123',
]);
```

## Requests and Responses

When you send a request to the SNMP host using the client, it wraps the request in a message object and sends it to the
remote system. Most requests will send a response back to the client. This response contains:

* The Message object (either MessageResponseV1, MessageResponseV2, MessageResponseV3), which depends on the version.
* The Message object will always contain the response via the `getResponse()` method.
* If the SNMP version is 3, then it will contain the MessageHeader and the SecurityParameters.

The message object is available when you send a generic request via the `send()` method of the SNMP client. When using
other shorthand methods on the SNMP client it will directly send back the most useful information related to the request,
such as an OidList.

```php
use FreeDSx\Snmp\Requests;
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
]);

# Perform a simple get request, which returns an OidList...
try {
   $oids = $snmp->get('1.3.6.1.2.1').PHP_EOL;
} catch (SnmpRequestException $e) {
  echo $e->getMessage().PHP_EOL;
  exit;
}

# Iterate through the OidList
foreach ($oids as $oid) {
    echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()).PHP_EOL;
}

# Perform a generic request via send, get the MessageResponse object back
try {
   $message = $snmp->send(Requests::get('1.3.6.1.2.1')).PHP_EOL;
} catch (SnmpRequestException $e) {
  echo $e->getMessage().PHP_EOL;
  exit;
}
var_dump($message);
```

If the request is not successful it will throw an SnmpRequestException. The exception has the code set to the SNMP error
code and the exception message will be a friendly message generated based off the code. You can also retrieve the SNMP
Message object that generated the exception from the exception object via the `getSnmpMessage()` method:

```php
try {
    $message = $snmp->send(Requests::get('1.3.6.1.2.1')).PHP_EOL;
} catch (SnmpRequestException $e) {
   # Get the full SNMP Message object (may be null depending on the context of the error)
   var_dump($e->getSnmpMessage());
   # Get the response object only (may be null depending on the context of the error)
   var_dump($e->getResponse());
   exit;
}
