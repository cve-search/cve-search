.. _db:

Database
========

CVE-Search makes use of multiple databases, these are:

* MongoDB
* Redis

MongoDB
#######

The MongoDB database is (by default) called cvedb and has 11 collections:

* cves (Common Vulnerabilities and Exposure items) - source NVD NIST (JSON)
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

Populating the database
-----------------------

For the initial run, you need to populate the CVE database by running:

.. code-block:: bash

    ./sbin/db_mgmt_cpe_dictionary.py -p
    ./sbin/db_mgmt_json.py -p
    ./sbin/db_updater.py -c # This will take >45minutes on a decent machine, please be patient

It will fetch all the existing JSON files from the Common Vulnerabilities
and Exposures feed and the Common Platform Enumeration. The initial
Common Platform Enumeration (CPE) import might take some time depending
on your configuration.

If you want to add the cross-references from NIST, Red Hat and other vendors thanks to `VIA4CVE <https://github.com/cve-search/VIA4CVE>`_:

.. code-block:: bash

    ./sbin/db_mgmt_ref.py

NB: If you want to  import your own JSON from VIA4CVE, you have to replace URL in sources.ini the VIA4 attribute with
`file:///PATH/TO/VIA4CVE/VIA4CVE-feed.json`.

.. _upd_db:

Updating the database
---------------------
An updater script helps to start the db_mgmt_*

.. code-block:: bash

    ./sbin/db_updater.py -v

You can run it in a crontab, logging is done in log/update_populate.log by default.

.. _repop_db:

Repopulating the database
-------------------------
To easily drop and re-populate all the databases

.. code-block:: bash

    ./sbin/db_updater.py -v -f

This will drop all the existing external sources and reimport everything. This operation can take some time
and it's usually only required when new attributes parsing are added in cve-search.

Redis
#####

4 Redis databases are used:

* Database number 9: Functions as a queue during populating and updating the MongoDB
* Database number 10: The cpe (Common Platform Enumeration) cache - source MongoDB cvedb collection cpe
* Database number 11: The notification database - source cve-search
* Database number 12: The `CVE reference database <https://cve.mitre.org/data/refs/>`_ is a cross-reference database to CVE IDs against various vendors ID - source NVD NIST/MITRE

Populating the database
-----------------------
Depending on the switches that are appended to the `./sbin/db_updater.py` command, the redis database will be populated.
Check the help of that specific script for further details.
