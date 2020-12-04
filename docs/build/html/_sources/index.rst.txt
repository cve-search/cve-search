CVE-Search
==========

.. image:: https://img.shields.io/github/release/cve-search/cve-search.svg
   :target: https://GitHub.com/cve-search/cve-search/releases/

.. image:: https://badges.gitter.im/Join%20Chat.svg
   :alt: Join the chat at https://gitter.im/cve-search/cve-search
   :target: https://gitter.im/cve-search/cve-search?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://img.shields.io/badge/License-GPLv3-blue.svg
   :target: https://www.gnu.org/licenses/gpl-3.0

.. image:: https://badgen.net/badge/Github/repo/green?icon=github
   :target: https://GitHub.com/cve-search/cve-search


CVE-Search is a tool to import CVE (Common Vulnerabilities and Exposures) and
CPE (Common Platform Enumeration) into a MongoDB to facilitate search
and processing of CVEs.

The main objective of the software is to avoid doing direct and public lookups
into the public CVE databases. Local lookups are usually faster and you can
limit your sensitive queries via the Internet.

CVE-Search includes a back-end to store vulnerabilities and related information,
an intuitive web interface for search and managing vulnerabilities,
a series of tools to query the system and a web API interface.

CVE-Search is used by many organizations including the `public CVE services of CIRCL <https://cve.circl.lu/>`_.

This document gives you basic information how to start with CVE-Search.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   getting_started/installation
   database/database
   webgui/webgui
   docker/docker
   software/software
   changelog/changelog
   license/license

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
