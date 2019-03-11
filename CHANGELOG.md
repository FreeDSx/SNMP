CHANGELOG
=========

0.4.0 (2019-03-11)
------------------
* Update the ASN.1 / Socket versions for performance / memory improvements.
* The SnmpWalk helper will now default to sending getBulk requests if the SNMP version is 2 or 3.
* Added a getOid() method to SnmpWalk as an alias of next().
* Allow a leading dot "." on OIDs being sent. It will strip the dot when encoding.

0.3.2 (2018-10-02)
------------------
* Fix privacy handling in the trap sink.
* Be more defensive about how exceptions are handled in the trap sink.
* Throw a more descriptive message if a PDU cannot be assembled after being decrypted.
* Update the privacy interface to be consistent.
* Add more specs around USM response types and privacy in general.

0.3.1 (2018-09-16)
------------------
* Fix handling of 64-bit counters (BigCounter). Suggest the GMP extension.

0.3.0 (2018-09-15)
------------------
* Provide a trap sink class to act as a server and collect incoming traps.
* Add better engine ID handling / the ability to generate and parse engine IDs.
* SNMP v3 traps are now sent using a locally generated engine ID / time.
* The context_engine_id option has been renamed to engine_id.
* Correct the order of the EngineId check on incoming messages.
* Validate the time window on incoming messages.
* Update the cached time, if applicable, based off current remote engine time.

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
