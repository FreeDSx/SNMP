CHANGELOG
=========

0.2.0 (2018-08-19)
------------------
* Provide an SNMP walker helper class with a simple API.
* Add better USM time synchronization.
* Authenticate incoming messages for USM.
* Generate proper IDs for SNMP v3 PDUs.
* Validate the ID number that was received.
* Restrict SNMP versions to only the PDUs that they support.
* Provide better USM related error messages.
* Throw an SnmpRequestException on unhandled Report PDUs.
* Make the SNMP Message nullable for SnmpRequestExceptions.

0.1.0 (2018-08-04)
------------------
* Tagging initial release.
