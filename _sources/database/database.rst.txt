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

For the initial run, you need to populate the CVE database by running:

.. code-block:: bash

    ./sbin/db_updater.py -f -c

It will fetch all the existing Common Vulnerabilities and Exposures (CVE) & Common Platform Enumeration (CPE) data from NVD NIST API,
and by default, the additional sources, too. The initial import might take some time depending on your configuration, e.g., over 45 minutes.
Please be patient.

This could be also run as a SystemD service. Example units are under `_etc/systemd/system/`:
`cvesearch.db_init.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_init.service>`_ &
`cvesearch.db_init.target <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_init.target>`_.

.. code-block:: bash

    sudo systemctl start --no-block cvesearch.db_init.target


Available additional sources are: CWE, CAPEC, VIA4 & EPSS. If you don't need some of them, they can be disabled through sources.ini.

Disabled sources can be updated one-shot with -s (--sources) which takes a list of available sources, e.g.,

.. code-block:: bash

    ./sbin/db_updater.py -s cwe capec via4 epss

The VIA4 are cross-references from NIST, Red Hat and other vendors thanks to `VIA4CVE <https://github.com/cve-search/VIA4CVE>`_:

NB: If you want to  import your own JSON from VIA4CVE, you have to replace URL in sources.ini the VIA4 attribute with
`file:///PATH/TO/VIA4CVE/VIA4CVE-feed.json`.

.. _upd_db:

Updating the database
---------------------
An updater script helps keeping the databases up-to-date and should be run at regular intervals.

.. code-block:: bash

    ./sbin/db_updater.py

Since CVE-Search v5.0.2 (using CveXplore v0.3.28) the updates have been using all of the sources more wisely; only changed data is downloaded.
For CPEs and CVEs this means entries that have been added or modified since last update, and for the rest of the source CVE-Search checks
whether the file has changed before downloading it. Therefore, it is now safe to run this, e.g., every hour. One option is to use crontab.
Logging is done in log/update_populate.log by default.

These could be also run as a SystemD service and a timer that automates regular updates. Example units are under `_etc/systemd/system/`:
`cvesearch.db_updater.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_updater.service>`_ &
`cvesearch.db_updater.timer <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_updater.timer>`_.

.. code-block:: bash

    sudo systemctl start cvesearch.db_updater.timer
    sudo systemctl enable cvesearch.db_updater.timer

In case some CVEs or CPEs are missing (only) during the last 1–120 days despite you have done regular updates, you can use -d 1..120
option to avoid repopulating the entire database. This could happen if there have been connectivity issues or other problems with
the NVD API. E.g., to manually set the update to download entries for the last 7 days from the NVD API:

.. code-block:: bash

    ./sbin/db_updater.py -d 7

Full option list is available with -h / --help.

.. _repop_db:

Repopulating the database
-------------------------
To easily drop and re-populate all the databases

.. code-block:: bash

    ./sbin/db_updater.py -f

This will drop all the existing external sources and reimport everything. This operation can take some time
and it's usually only required when new attributes parsing are added in cve-search.

This could be also run as a SystemD service. Example units are under `_etc/systemd/system/`:
`cvesearch.db_repopulate.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_repopulate.service>`_ &
`cvesearch.db_repopulate.target <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.db_repopulate.target>`_.
Using the service will stop `cvesearch.web.service <https://github.com/cve-search/cve-search/blob/master/_etc/systemd/system/cvesearch.web.service>`_
during the repopulation. This becomes handy as the web GUI & CVE-Search API would give errors or incomplete data during the process.

.. code-block:: bash

    sudo systemctl start --no-block cvesearch.db_repopulate.target


Redis
#####

3 Redis databases are used:

* Database number 10: The cpe (Common Platform Enumeration) cache - source MongoDB cvedb collection cpe
* Database number 11: The notification database - source cve-search
* Database number 12: The `CVE reference database <https://cve.mitre.org/data/refs/>`_ is a cross-reference database to CVE IDs against various vendors ID - source NVD NIST/MITRE


Populating the database
-----------------------
Depending on the switches that are appended to the `./sbin/db_updater.py` command, the redis database will be populated.
Check the help of that specific script for further details.
