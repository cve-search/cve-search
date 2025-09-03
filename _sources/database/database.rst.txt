.. _db:

Database
========

CVE-Search makes use of multiple databases, these are:

* MongoDB
* Redis

MongoDB
#######

The MongoDB database is (by default) called cvedb and has 11 collections:

* cves (Common Vulnerabilities and Exposure items) - source NVD NIST (API)
* cpe (Common Platform Enumeration items) - source NVD NIST
* cwe (Common Weakness Enumeration items) - source NVD NIST
* capec (Common Attack Pattern Enumeration and Classification) - source NVD NIST
* ranking (ranking rules per group) - local cve-search
* `MITRE Reference Key/Maps <https://cve.mitre.org/data/refs/>`_ - source MITRE reference Key/Maps
* info (metadata of each collection like last-modified) - local cve-search
* via4 `VIA4CVE <https://github.com/cve-search/VIA4CVE>`_ cross-references, and has 3 additional sources:
    * `MITRE Reference Key/Maps <https://cve.mitre.org/data/refs/>`_.
    * Red Hat RPM to CVE database.
    * Red Hat RHSA Oval database.

The initial setup of CVE-Search happens only once, at the installation.
This consists of two steps and one optional step.

 * Populating the database
 * *Optional:* You can also run the "Other CPE Dictionary" script to help fill in the blanks
 * Updating the database

.. _pop_db:

Connecting to MongoDB
---------------------

MongoDB has two possible syntax for connecting to the database.

* `mongodb://` - Default
* `mongodb+srv://`

The default syntax allows for connectivity to a single host or a replica set.  The SRV syntax
allows for connecting using a  single DNS hostname which seeds multiple hosts in a replica set.
The SRV DNS record contains all of the details required for connecting to any server contained
in a replia set, even if one of the nodes is unavailable.

To enable the SRV scheme, set the variable `DnsSrvRecord` to `True` in the configuration.ini file.
For more information, read `MongoDB 3.6: Here to SRV you with easier replica set connections <https://www.mongodb.com/developer/article/srv-connection-strings/>`_.

*Note:* MongoDB Atlas requires the use of the SRV syntax.

Database User Authentication
----------------------------

When passing a username and password, CVE-Search submits the values against the default `admin` 
database. If the authentication information is stored in a database other than `admin`, 
authentication attempts will fail.

To change the default authentiation database, set the variable `AuthDB` in the configuration.ini file.

Populating the database
-----------------------

For the initial run, populate the database by executing:

.. code-block:: bash

    ./sbin/db_updater.py -f

This fetches all existing Common Vulnerabilities and Exposures (CVE) and Common Platform Enumeration (CPE) data from the NVD NIST API.  
By default, it also includes additional external sources. Available additional sources include: CWE, CAPEC, VIA4 & EPSS.
If you don't need some of them, they can be disabled through `sources.ini`.

The initial import may take some time — depending on your system and network setup, it could exceed two hours. Please be patient.

This can also be run as a SystemD service. Example units are under `_etc/systemd/system/`:  
`cvesearch.db_init.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_init.service>`_ &  
`cvesearch.db_init.target <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_init.target>`_.

.. code-block:: bash

    sudo systemctl start --no-block cvesearch.db_init.target

The initialization target ensures conflicting services like `cvesearch.web.service` are stopped during this one-time operation.

Disabled sources can be updated one-shot with the `-s` (`--sources`) option, which takes a list of available sources, e.g.,

.. code-block:: bash

    ./sbin/db_updater.py -s cwe capec via4 epss

The VIA4 data are cross-references from NIST, Red Hat, and other vendors thanks to `VIA4CVE <https://github.com/cve-search/VIA4CVE>`_:

Note: If you want to import your own JSON from VIA4CVE, replace the URL in `sources.ini` for the VIA4 attribute with  
`file:///PATH/TO/VIA4CVE/VIA4CVE-feed.json`.

.. _upd_db:

Updating the database
---------------------

An updater script helps keep the databases up-to-date and should be run regularly.

.. code-block:: bash

    ./sbin/db_updater.py

In case an update for a specific data source fails, you can ensure updates from the other sources by running them one at a time:

.. code-block:: bash

    ./sbin/db_updater.py -s cpe
    ./sbin/db_updater.py -s cve
    ./sbin/db_updater.py -s cwe
    ./sbin/db_updater.py -s capec
    ./sbin/db_updater.py -s via4
    ./sbin/db_updater.py -s epss

Alternatively, you can update groups of sources together:

.. code-block:: bash

    ./sbin/db_updater.py -s cpe cve
    ./sbin/db_updater.py -s cwe capec via4 epss

Since CVE-Search v5.0.2 (using CveXplore v0.3.28), updates use all sources more efficiently; only changed data is downloaded.  
For CPEs and CVEs, this means entries added or modified since the last update, and for other sources, CVE-Search checks if the file changed
before downloading it. Therefore, it is safe to run this, for example, every hour.

Logging is done by default to `log/update_populate.log`.

These can also be run as a SystemD service and timer that automate regular updates. Example units are under `_etc/systemd/system/`:  
`cvesearch.db_updater.target <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_updater.target>`_,  
`cvesearch.db_updater@.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_updater@.service>`_,  
`cvesearch.db_updater.timer <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_updater.timer>`_,  
and the ordering drop-in unit for the `cve` source:  
`ordering.conf <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_updater@cve.service.d/ordering.conf>`_.

The target unit coordinates all updater instances, applying ordering constraints via this drop-in on the `cve` instance to ensure correct sequencing.

.. code-block:: bash

    sudo systemctl start cvesearch.db_updater.timer
    sudo systemctl enable cvesearch.db_updater.timer

In case some CVEs or CPEs are missing (only) during the last 1–120 days despite having performed regular updates, you can use the `-d`
option with a value from 1 to 120 to avoid repopulating the entire database. This situation can occur due to temporary connectivity issues
or other problems with the NVD API. For example, to manually trigger an update that fetches entries from the last 7 days from the NVD API:

.. code-block:: bash

    ./sbin/db_updater.py -d 7

Full option list is available with `-h` / `--help`.

.. _repop_db:

Repopulating the database
-------------------------

Since CVE-Search v5.1.0, database repopulation is functionally identical to initialization.

To drop and re-populate all databases:

.. code-block:: bash

    ./sbin/db_updater.py -f

This will remove all existing external source data and reimport everything from scratch.  
Repopulation can take some time and is typically only required after changes to CVE-Search's attribute parsing or data model.

This can also be run as a SystemD service. Example units are under `_etc/systemd/system/`:  
`cvesearch.db_init.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_init.service>`_ &  
`cvesearch.db_init.target <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_init.target>`_.

(The legacy example units have been retired as duplicates:
`cvesearch.db_repopulate.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_repopulate.service>`_ &  
`cvesearch.db_repopulate.target <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_repopulate.target>`_.)

The initialization/repopulation target ensures conflicting services like `cvesearch.web.service` are stopped during the operation,
preventing errors or incomplete data in the web GUI and API.

.. code-block:: bash

    sudo systemctl start --no-block cvesearch.db_init.target


Redis
#####

2 Redis databases are used:

* Database number 10: The CPE (Common Platform Enumeration) cache - source MongoDB cvedb collection cpe
* Database number 11: The notification database - source cve-search

Enabling Redis caching
----------------------

To enable Redis caching when populating or updating the database, add the `-c` flag to `./sbin/db_updater.py`:

* Full initialization or repopulation: `./sbin/db_updater.py -f -c`
* Updating all databases at once: `./sbin/db_updater.py -c`
* Updating only the CPE database (the only one supporting caching): `./sbin/db_updater.py -s cpe -c`

SystemD drop-in support
-----------------------

The example SystemD units have drop-ins & units that enable Redis caching:

* For database initialization and repopulation: 
  `cvesearch.db_init.service.d/redis-cache.conf <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_init.service.d/redis-cache.conf>`_
* For CPE-specific updates: 
  `cvesearch.db_updater.cpe.redis_cache.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_updater.cpe.redis_cache.service>`_  
  and `.timer <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_updater.cpe.redis_cache.timer>`_

To enable regular CPE Redis cache updates:

.. code-block:: bash

    sudo systemctl start cvesearch.db_updater.cpe.redis_cache.timer
    sudo systemctl enable cvesearch.db_updater.cpe.redis_cache.timer
