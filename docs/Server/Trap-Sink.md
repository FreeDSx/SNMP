Trap Sink
================

* [Configuration](#configuration)
* [General Usage](#general-usage)

The Trap Sink acts as a server to receive SNMP (v1, v2, v3) traps from hosts. Received traps are passed to a user defined
listener object that then processes it. 

**Note**: The trap sink currently does not support SNMPv3 inform requests. However, SNMPv2 inform requests are supported.

## Configuration

* [General Options](#general-options)
    * [ip](#ip)
    * [port](#port)
    * [version](#version)
    * [community](#community)
    * [whitelist](#whitelist)
    * [timeout_connect](#timeout_connect)

------------------
#### ip

The IP address for the trap sink to bind to.

**Default**: `0.0.0.0`

------------------
#### port

The port to listen for traps on.

**Default**: `162`

------------------
#### version

Only accept traps using this SNMP version.

**Default**: `(null)`

------------------
#### community

Only accept traps from this SNMP community.

**Default**: `(null)`

------------------
#### whitelist

An array of IP addresses permitted to send traps to this trap sink. If a trap is received from an IP address that is not
on the whitelist then it will be ignored. Defined like: `['192.168.1.1', '127.0.0.1']`

If you define this, then the `accept()` method of the listener is never called.

**Default**: `(null)`

------------------
#### timeout_connect

When sending an inform request, this is the timeout period (in seconds) when connecting to the SNMP host for the response.

**Default**: `5`
    
## General Usage

To use the trap sink you must define a listener class. The listener class must implement the TrapListenerInteface, which
defines what methods you must define on your trap listener when using the trap sink.

The methods you must define on the listener are as follows:

```php
# FreeDSx\Snmp\Trap\TrapListenerInterface

/**
 * Whether or not the host should be accepted. Return true to allow the trap, return false to deny it.
 *
 * @param string $ip
 * @return bool
 */
public function accept(string $ip) : bool;

/**
 * Given an engineId, get the USM user information associated with it. This information is used to potentially
 * authenticate and/or decrypt an incoming SNMP v3 trap using the USM security model.
 *
 * To ignore a request by a specific engine ID and user, return null.
 *
 * @param EngineId $engineId
 * @param string $user
 * @return UsmUser
 */
public function getUsmUser(EngineId $engineId, string $ip, string $user) : ?UsmUser;

/**
 * Handle a received trap.
 *
 * @param TrapContext $context
 */
public function receive(TrapContext $context) : void;
```

So first create your own class implementing the above interface to pass to the trap sink, such as:

```php
use FreeDSx\Snmp\Trap\TrapListenerInterface;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Module\SecurityModel\Usm\UsmUser;

class TrapListener implements TrapListenerInterface
{
    /**
     * @var array
     */    
    protected $users = [];
    
    public function __construct()
    {
        $user1 = UsmUser::withPrivacy('user1', 'auth-password123', 'sha512', 'priv-password123','aes128');
        
        $this->users[EngineId::fromText('foobar123')->toBinary()]['user1'] = $user1;
    }
    
    /**
     * {@inheritdoc}
     */
    public function accept(string $ip) : bool
    {
        # Implement any logic here for IP addresses you want to accept / decline...
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsmUser(EngineId $engineId, string $ipAddress, string $user) : ?UsmUser
    {
        # Assuming we have an array populated with the engine and users associated with it...
        if (isset($this->users[$engineId->toBinary()]) && isset($this->>users[$engineId->toBinary()][$user])) {
            return $this->users[$engineId->toBinary()][$user];            
        }
        
        return null;
    }
    
    /**
     * {@inheritdoc}
     */
    public function receive(TrapContext $context) : void
    {
        # The full SNMP message
        $message = $context->getMessage();
        # The IP address the trap came from
        $ipAddress = $context->getIpAddress();
        # The trap request object only
        $trap = $context->getTrap();
        # The SNMP version that was used
        $version = $context->getVersion();
    }
}
```

Then pass it to the trap sink when constructing it:

```php
use FreeDSx\Snmp\TrapSink;

$listener = new TrapListener();
$trapSink = new TrapSink($listener);
$trapSink->listen();
```
