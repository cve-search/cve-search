# Changelog


## v5.1.0 (2024-07-13)

### Changes

* Retire db_mgmt_[source].py (#1113) [Esa Jokinen]
  * **Caution!** Possibly backwards incompatible change as the procedure for
    initial population of the database has changed. Please revise the
    [documentation](https://cve-search.github.io/cve-search/database/database.html#populating-the-database)
    and update your SystemD cvesearch.db_init.service based on the updated example.
  * All these features are now available through db_updater.py --sources option.
* Pass configuration to CveXplore [Esa Jokinen]
  * Pass sources configuration to CveXplore (#1112)
  * Pass MongoDB configuration to CveXplore (#1107)
  * Pass proxy configuration to CveXplore (#1102)
  * Set sources & update interval manually for NVD API (#1110)
* Fix sort_dir in free queries (#1109) [Giuseppe Crea]
* Fix default config & remove unused imports (#1108) [Esa Jokinen]

### Other

* Update CveXplore dependency from 0.3.30 to 0.3.35 with many improvements, e.g.,
  * Set update interval (1–120 days) manually for NVD API
  * Fix MongoDB dbname, user & password configuration with & without credentials
  * Improve error logging of NVD API
  * Ignore EPSS for rejected CVEs; fixes sorting of DataTables (#1103)
    * **Caution!** Updates database schema; requires repopulation
      (or [manual cleanup](https://github.com/cve-search/cve-search/issues/1103#issuecomment-2198044483)).
  * Updates PyMongo to 4.8.0 with [fallback to stdlib ssl](https://github.com/mongodb/mongo-python-driver/pull/1669)
    when PyOpenSSL (< 23.2.0) import fails with AttributeError due to incompatible
    versions with cryptography (>= 42.0.0).


## v5.0.3 (2024-04-16)

### Changes

* [changelog] updated for release 5.0.2. [Alexandre Dulaunoy]

### Other

* Update requirements.txt. [PT]


## v5.0.2 (2024-04-13)

### Changes

* [VERSION] release 5.0.2. [Alexandre Dulaunoy]

* [changelog] updated. [Alexandre Dulaunoy]

### Other

* Update requirements.txt. [PT]

* Update requirements.txt. [PT]

* Support non-numeric versions in relaxSearch (#1081) [Esa Jokinen]

  * Support non-numeric versions in relaxSearch
  Use simplified version string for easier comparison.
  Avoid using print() in a library.

  * New unit tests for improved search.py --lax

  * Fix search.py bug with parentheses in version

  * Corrections for search.py help in README.md

  * Fix import order for lib.cpe_conversion

  * README.md lint markdown, syntax highlighting etc.

  * Black formatting

  * README.md further improve jq highlighting

* Fix CPE name parsing (#1080) [Maxime Huyghe]

* Update web/VERSION 5.0.1.dev16. [GitHub Action]

* Bump cryptography from 42.0.0 to 42.0.4 (#1060) [dependabot[bot]]

  Bumps [cryptography](https://github.com/pyca/cryptography) from 42.0.0 to 42.0.4.
  - [Changelog](https://github.com/pyca/cryptography/blob/main/CHANGELOG.rst)
  - [Commits](https://github.com/pyca/cryptography/compare/42.0.0...42.0.4)

  ---
  updated-dependencies:
  - dependency-name: cryptography
    dependency-type: direct:production
  ...

* Update auto_version.yaml. [PT]

* Refactor db_updater fixing repopulate ordering & removing -v option (#1076) [Esa Jokinen]

  * db_updater: fix repopulate ordering

  * db_updater: more informative log headers

  * db_updater: only drop collections on first iteration

  * db_updater: drop non-configured collections

  * Remove -v option from dp_updater

  Leave dummy option for backwards compatibility.
  Clarify the documentation.

  * Use same instance of CveXplore() & add main

* SystemD db_updater.timer lower update interval (#1078) [Esa Jokinen]

* Cleanup: remove unused .talismanrc fileignore (#1075) [Esa Jokinen]

* Gitignore entire docs/build (#1074) [Esa Jokinen]

* GitHub workflow for automatic web/VERSION update (#1073) [Esa Jokinen]

* Sync configuration.ini.sample with Config.py & update docs (#1071) [Esa Jokinen]

* Upgrade workflow actions to Node.js 20 (#1072) [Esa Jokinen]

* Downgrade DataTables 2.0.3 -> 1.13.11 (#1067) [Esa Jokinen]

* Major documentation updates (#1069) [Esa Jokinen]

* Improve SystemD service examples (#1065) [Esa Jokinen]

* Update static JS dependencies (#1063) [Esa Jokinen]

  * Update jQuery 3.6.0 -> 3.7.1

  * Update Popper v2.11.5 -> v2.11.8

  * Update clipboard.js v2.0.10 -> v2.0.11

  * Update Bootstrap v4.6.0 -> v4.6.2

  "One of our last releases for the v4."

  * Update DataTables 1.11.3 -> 2.0.3

* Fixes #1057. [Paul Tikken]

* Req bump. [Paul Tikken]


## v5.0.1 (2024-01-28)

### New

* [release] changelog updated to match release v5.0.0. [Alexandre Dulaunoy]

### Other

* Update README.md (#1055) [Esa Jokinen]

  * systemd services: rename mongod.service

  * black formatting

  * README.md add workflow badges

  * README.md update copyright years

  * README.md update changelog link

  The changelog on the site hasn't been updated for ages.

* Systemd services: rename mongod.service (#1052) [Esa Jokinen]

  * systemd services: rename mongod.service

  * black formatting

  * README.md add workflow badges

* Update script tweaks (#1051) [PT]

  * tweaks to update script

* Add check for missing 'vulnerable_configuration' field (#1050) [PT]

* Fixes #1038. [Paul Tikken]

* Merge pull request #1047 from cve-search/cve-search-1042. [PT]

  Additional check

* Added check for missing epss values. [Paul Tikken]

* Merge pull request #1041 from oh2fih/master. [PT]

  Add workflow to check black formatting

* Black formatting (23.12.1) [Esa Jokinen]

* Add workflow to check black formatting. [Esa Jokinen]

* Black formatting. [Paul Tikken]


## v5.0.0 (2023-12-18)

### New

* [ChangeLog] added. [Alexandre Dulaunoy]

### Other

* Update requirements.txt. [PT]

* Merge pull request #1034 from baonq-me/fix/12122023_cli_search_cve. [PT]

* Fix counting results when searching for CVE using cli. [baonq-me]

* Merge pull request #1033 from baonq-me/master. [PT]

* Improve CVEs search speed in bin/search.py. [baonq-me]

  Improve CVEs search speed in bin/search.py by passing search query to mongodb instead of getting all ids, then calling db again to get each doc. Some case like "bin/search.py -s linux" can return seven thousand CVEs which result to seven thousand API calls to db by the old way.

* Allow getting CVEs from a MongoDB doc. [baonq-me]

  Sometimes we need to getting so many CVE from the database. It's better to getting all mongo doc at the same time to reduce network calls to the database, then use method getCveFromMongoDbDoc() to standardize the document

* Add method searchCVE to DatabaseLayer. [baonq-me]

* Merge pull request #1031 from fazledyn-or/Fix_Inappropriate_Logic. [PT]

  Fixed Inappropriate Logical Expression

* Fixed Inappropriate Logical Expression. [fazledyn-or]

* Merge pull request #1032 from baonq-me/fix/11122023_mongodb_count. [PT]

  Use count_documents() to count mongo documents instead of old and deprecated count()

* Use method count_documents to count mongo documents instead of old and deprecated count() [baonq-me]

* Merge pull request #1030 from baonq-me/fix/08122023_mongodb_connection. [PT]

* Pass mongodb connection string when initialize CveXplore. [baonq-me]

* Commented out code coverage. [Paul Tikken]

* Fixes #916. [Paul Tikken]

* Update requirements.txt. [PT]

* Merge pull request #1022 from cve-search/CveSearch-1021. [PT]

  mongodb connections

* Fixes #1021. [Paul Tikken]

* Req update. [Paul Tikken]

* Merge pull request #1019 from cve-search/fix_1017. [PT]

  wrong key when populating redis cache

* Should address #1017. [Paul Tikken]

* Update requirements.txt. [PT]

* Merge pull request #1010 from cve-search/cve-search-929. [PT]

  Rewrite of database update to use NVD NIST API from cvexplore lib

* Update web/templates/cve.html. [PT]

* Temp disabling failing test; they break on changed datastructure and need to be revised. [Paul Tikken]

* Temp disabling failing test; they break on changed datastructure and need to be revised. [Paul Tikken]

* Temp disabling failing test; they break on changed datastructure and need to be revised. [Paul Tikken]

* Altered test data to match new structure. [Paul Tikken]

* Reqs update. [Paul Tikken]

* Reqs update. [Paul Tikken]

* Workflow update. [Paul Tikken]

* Workflow update. [Paul Tikken]

* Updated reqs. [Paul Tikken]

* First refactor which makes use of cvexplore for database updates vai NIST NVD API. [Paul Tikken]

* Optimized imports. [Paul Tikken]

* Merge pull request #1002 from nsmfoo/master. [PT]

  Update requirements.txt

* Update requirements.txt. [Mikael Keri]

  Specified the flask-menu version. The latest release of the module (v1.0.0) currently breaks the cve-search webinterface

* Delete .github/workflows/codeql-analysis.yml. [PT]

* Merge pull request #998 from oh2fih/master. [PT]

  Configurable DownloadMaxWorkers (#890)

* Fix beautifulsoup4 required version mismatch requirements-dev.txt (4.10.0) behind requirements.txt (4.11.0) [Esa Jokinen]

* Fix Build & Test pipeline (codecov) Use version of codecov (2.1.13) that is still available. [Esa Jokinen]

* Handle configuration errors in DownloadMaxWorkers. [Esa Jokinen]

* Configurable DownloadMaxWorkers (#890) [Esa Jokinen]


## v4.2.2 (2023-08-08)

### Other

* Merge pull request #990 from oh2fih/master. [PT]

* Black formatting (23.7.0) [Esa Jokinen]

* DownloadHandler.store_file() accept "text/xml" [Esa Jokinen]

  The CAPEC source uses this Content-Type now instead of "application/xml"

* Merge pull request #956 from cve-search/dependabot/pip/redis-4.5.4. [PT]

* Bump redis from 4.5.3 to 4.5.4. [dependabot[bot]]

  Bumps [redis](https://github.com/redis/redis-py) from 4.5.3 to 4.5.4.
  - [Release notes](https://github.com/redis/redis-py/releases)
  - [Changelog](https://github.com/redis/redis-py/blob/master/CHANGES)
  - [Commits](https://github.com/redis/redis-py/compare/v4.5.3...v4.5.4)

  ---
  updated-dependencies:
  - dependency-name: redis
    dependency-type: direct:production
  ...

* Merge pull request #957 from cve-search/dependabot/pip/docs/source/redis-4.4.4. [PT]

* Bump redis from 3.5.3 to 4.4.4 in /docs/source. [dependabot[bot]]

  Bumps [redis](https://github.com/redis/redis-py) from 3.5.3 to 4.4.4.
  - [Release notes](https://github.com/redis/redis-py/releases)
  - [Changelog](https://github.com/redis/redis-py/blob/master/CHANGES)
  - [Commits](https://github.com/redis/redis-py/compare/3.5.3...v4.4.4)

  ---
  updated-dependencies:
  - dependency-name: redis
    dependency-type: direct:production
  ...

* Merge pull request #954 from cve-search/dependabot/pip/redis-4.5.3. [PT]

* Bump redis from 4.2.2 to 4.5.3. [dependabot[bot]]

  Bumps [redis](https://github.com/redis/redis-py) from 4.2.2 to 4.5.3.
  - [Release notes](https://github.com/redis/redis-py/releases)
  - [Changelog](https://github.com/redis/redis-py/blob/master/CHANGES)
  - [Commits](https://github.com/redis/redis-py/compare/v4.2.2...v4.5.3)

  ---
  updated-dependencies:
  - dependency-name: redis
    dependency-type: direct:production
  ...

* Merge pull request #952 from dbarzin/patch-3. [PT]

* Add mercator. [Didier Barzin]

* Merge pull request #939 from cve-search/dependabot/pip/nested-lookup-0.2.25. [Alexandre Dulaunoy]

  Bump nested-lookup from 0.2.23 to 0.2.25

* Bump nested-lookup from 0.2.23 to 0.2.25. [dependabot[bot]]

  Bumps [nested-lookup](https://git.unturf.com/python/nested-lookup) from 0.2.23 to 0.2.25.

  ---
  updated-dependencies:
  - dependency-name: nested-lookup
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #938 from cve-search/dependabot/pip/jsonpickle-3.0.1. [Alexandre Dulaunoy]

  Bump jsonpickle from 2.1.0 to 3.0.1

* Bump jsonpickle from 2.1.0 to 3.0.1. [dependabot[bot]]

  Bumps [jsonpickle](https://github.com/jsonpickle/jsonpickle) from 2.1.0 to 3.0.1.
  - [Release notes](https://github.com/jsonpickle/jsonpickle/releases)
  - [Changelog](https://github.com/jsonpickle/jsonpickle/blob/main/CHANGES.rst)
  - [Commits](https://github.com/jsonpickle/jsonpickle/compare/v2.1.0...v3.0.1)

  ---
  updated-dependencies:
  - dependency-name: jsonpickle
    dependency-type: direct:production
    update-type: version-update:semver-major
  ...

* Merge pull request #931 from cve-search/dependabot/pip/sphinx-5.3.0. [PT]

* Bump sphinx from 4.3.1 to 5.3.0. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 4.3.1 to 5.3.0.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/master/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v4.3.1...v5.3.0)

  ---
  updated-dependencies:
  - dependency-name: sphinx
    dependency-type: direct:development
    update-type: version-update:semver-major
  ...

* Merge pull request #920 from oh2fih/master. [PT]

* Black formatting. [Esa Jokinen]

* Merge pull request #919 from GalaxyGamingBoy/master. [PT]

* Merge pull request #4 from GalaxyGamingBoy/CORS. [GalaxyGamingBoy]

  Reformatted

* Reformatted. [GalaxyGamingBoy]

* Merge pull request #3 from GalaxyGamingBoy/CORS. [GalaxyGamingBoy]

  Simplified IF clause

* Simplified. [GalaxyGamingBoy]

* Merge pull request #2 from GalaxyGamingBoy/CORS. [GalaxyGamingBoy]

  Limited CORS to API

* Limited CORS to API. [GalaxyGamingBoy]

* Merge pull request #1 from GalaxyGamingBoy/CORS. [GalaxyGamingBoy]

  Added CORS Support, can be changed via config

* Added CORS Support, can be changed via config. [GalaxyGamingBoy]

* Merge pull request #904 from dbarzin/patch-2. [PT]

* Update README.md. [Didier Barzin]

  Add link to Mercator

* Merge pull request #896 from dbarzin/master. [PT]

* Update install documentation for Ubuntu 22.04. [dbarzin]

* Merge pull request #895 from dbarzin/patch-1. [PT]

* Upgrade README.md. [Didier Barzin]

  show all options of search.py


## v4.2.1 (2022-05-27)

### New

* [config] changelogrc configuration + updated pattern for tag matching. [Alexandre Dulaunoy]

### Changes

* [release] version 4.2.1. [Alexandre Dulaunoy]

### Other

* Merge pull request #888 from oh2fih/master. [PT]

* Black formatting for lib/Config.py. [Esa Jokinen]

* Use CVEMaxLimit in /api/cvefor and /api/last. [Esa Jokinen]

* Add configurable [API] CVEMaxLimit. [Esa Jokinen]

* Black formatting (web/) [Esa Jokinen]

* Rename the maximum limit variable. [Esa Jokinen]

* Set default limit & max limit for /api/cvefor. [Esa Jokinen]

* Merge pull request #884 from oh2fih/master. [PT]

* Merge branch 'update-js-dependencies' [Esa Jokinen]

* Update Bootstrap v4.6.0 -> v4.6.1. [Esa Jokinen]

* Update clipboard.js v2.0.8 -> v2.0.10. [Esa Jokinen]

* Update Popper v2.10.1 -> v2.11.5. [Esa Jokinen]

* Update DataTables 1.11.2 -> 1.11.3. [Esa Jokinen]

  Not changed:
  - [1.11.3]/js/dataTables.bootstrap4.min.js
  - [1.11.3]/css/dataTables.bootstrap4.min.css

* Merge pull request #883 from oh2fih/master. [PT]

* Update rest api documentation to meet with PR #880. [Esa Jokinen]

* Merge pull request #880 from oh2fih/master. [PT]

  Fix CPE conversions

* Use cpe_conversion library in Toolkit.py. [Esa Jokinen]

* Black formatting. [Esa Jokinen]

* Rename library to match its purpose. [Esa Jokinen]

* Merge pull request #2 from rg-atte/master. [Esa Jokinen]

  Added cve conversion library

* EOF newline. [Atte]

* Functionality to correctly convert CPE versions. [Atte]

* Merge pull request #878 from AlphaBravoCompany/master. [PT]

* Add authentication database variables (#3) [Ed Engelking]

  * Added authSource to DB connection call. Updated configuration sample with variable.

  * Updated documentation

  * Updated documentation wording

* Updated github actions python versions to 3.8. [Paul Tikken Laptop]

* Updated github actions python versions to 3.8. [Paul Tikken Laptop]

* Merge pull request #869 from P-T-I/cve-search-858. [PT]

  Capec 3.7 update

* Capec sources updated to 3.7. [Paul Tikken Laptop]

* Update requirements.txt. [Paul Tikken Laptop]

* Merge pull request #848 from cve-search/dependabot/pip/nltk-3.7. [PT]

  Bump nltk from 3.6.5 to 3.7

* Bump nltk from 3.6.5 to 3.7. [dependabot[bot]]

  Bumps [nltk](https://github.com/nltk/nltk) from 3.6.5 to 3.7.
  - [Release notes](https://github.com/nltk/nltk/releases)
  - [Changelog](https://github.com/nltk/nltk/blob/develop/ChangeLog)
  - [Commits](https://github.com/nltk/nltk/compare/3.6.5...3.7)

  ---
  updated-dependencies:
  - dependency-name: nltk
    dependency-type: direct:production
    update-type: version-update:semver-minor
  ...

* Merge pull request #856 from cve-search/dependabot/pip/pytest-7.1.1. [PT]

  Bump pytest from 6.2.5 to 7.1.1

* Bump pytest from 6.2.5 to 7.1.1. [dependabot[bot]]

  Bumps [pytest](https://github.com/pytest-dev/pytest) from 6.2.5 to 7.1.1.
  - [Release notes](https://github.com/pytest-dev/pytest/releases)
  - [Changelog](https://github.com/pytest-dev/pytest/blob/main/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest/compare/6.2.5...7.1.1)

  ---
  updated-dependencies:
  - dependency-name: pytest
    dependency-type: direct:production
    update-type: version-update:semver-major
  ...

* Merge pull request #862 from cve-search/dependabot/pip/requests-2.27.1. [PT]

  Bump requests from 2.26.0 to 2.27.1

* Bump requests from 2.26.0 to 2.27.1. [dependabot[bot]]

  Bumps [requests](https://github.com/psf/requests) from 2.26.0 to 2.27.1.
  - [Release notes](https://github.com/psf/requests/releases)
  - [Changelog](https://github.com/psf/requests/blob/main/HISTORY.md)
  - [Commits](https://github.com/psf/requests/compare/v2.26.0...v2.27.1)

  ---
  updated-dependencies:
  - dependency-name: requests
    dependency-type: direct:production
    update-type: version-update:semver-minor
  ...

* Merge pull request #865 from cve-search/dependabot/pip/docs/source/nltk-3.6.6. [PT]

  Bump nltk from 3.6.5 to 3.6.6 in /docs/source

* Bump nltk from 3.6.5 to 3.6.6 in /docs/source. [dependabot[bot]]

  Bumps [nltk](https://github.com/nltk/nltk) from 3.6.5 to 3.6.6.
  - [Release notes](https://github.com/nltk/nltk/releases)
  - [Changelog](https://github.com/nltk/nltk/blob/develop/ChangeLog)
  - [Commits](https://github.com/nltk/nltk/compare/3.6.5...3.6.6)

  ---
  updated-dependencies:
  - dependency-name: nltk
    dependency-type: direct:production
  ...

* Merge pull request #864 from AlphaBravoCompany/master. [PT]

  Database connectivity using MONGODB+SRV connection string

* Database connectivity using MONGO+SRV connection string (#2) [Ed Engelking]

  * Added feature to use mongodb-srv URI records in mongodb plugin. Added URI configuration options in Config.py. Updated sample configuration to include ability to enable mongodb-srv URI. Added dnspython to pip requirements.txt.

  * Updating database documentation to explain how to use the new configuration options for SRV syntax.

  * Fixed a word.

  * Updated Config.py and mongodb.py to allow calls for SRV connections.

* Update VERSION. [PT]

* Merge pull request #854 from oh2fih/master. [PT]

* Remove logrotate as logging to syslog. [Esa Jokinen]

* A more complete set of CVE-Search systemd services. [Esa Jokinen]

* Merge pull request #831 from FafnerKeyZee/patch-1. [PT]

* Sending parameters to make uwsgi happy ;) [Fafner [_KeyZee_]]

* Merge pull request #830 from FafnerKeyZee/master. [PT]

* Adding systemd and logrotate. [Olivier Ferrand]

* Merge pull request #824 from cve-search/dependabot/pip/sphinx-4.3.1. [Alexandre Dulaunoy]

  Bump sphinx from 4.3.0 to 4.3.1

* Bump sphinx from 4.3.0 to 4.3.1. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 4.3.0 to 4.3.1.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/4.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v4.3.0...v4.3.1)

  ---
  updated-dependencies:
  - dependency-name: sphinx
    dependency-type: direct:development
    update-type: version-update:semver-patch
  ...

* Merge pull request #816 from kawtar01/feature/setup_oidc_auth_flow. [PT]

* Update doc to elaborate idp discovery url. [Kawtar.ahaggach.e]

* Update requirements.txt. [Paul Tikken Laptop]

* Rebase. [Paul Tikken Laptop]

* Merge pull request #823 from P-T-I/api_doc_fix. [PT]

  Redoc dependency removal

* Removed redoc as dependency. [Paul Tikken Laptop]

* Merge pull request #822 from P-T-I/update_reqs. [PT]

  Updated requirements

* Updated requirements. [Paul Tikken Laptop]

* Fix for always showing the bottom plugin toolbar. [Paul Tikken Laptop]

* Merge pull request #819 from P-T-I/cve-search-801. [PT]

  Updates capec version

* Fix #cve-search-801; update capec version. [Paul Tikken Laptop]

* Changed print statements to logger statements. Added function to retrieve a requests session instead of a plain request method. This function also respects proxies from the config. Added verify possibility to ignore requests made with/to self signed certificates OIDC servers. Black formatting enforced. [Paul Tikken Laptop]

* Black formatting and cleanup imports. [Paul Tikken Laptop]

* Added SSL_Verify to Config.py and corresponding method to retrieve the value. Added this value into the configuration.ini.sample as well. [Paul Tikken Laptop]

* Setup OIDC login flow. [Kawtar.ahaggach.e]

* Merge pull request #814 from FafnerKeyZee/master. [PT]

* Update bookmarked.html. [Fafner [_KeyZee_]]

* Update linked.html. [Fafner [_KeyZee_]]

* Merge pull request #806 from oh2fih/master. [PT]

  Enhance sanitation #796 + black formatting.

* Black formatting. [Esa Jokinen]

* Enhance sanitation #796 + black formatting. [Esa Jokinen]

* Merge pull request #796 from P-T-I/cve-search-795. [PT]

  Reflected server-side cross-site scripting

* Update requirements. [Paul Tikken Laptop]

* Fix #795; server side XSS vulnerability. [Paul Tikken Laptop]

* Merge pull request #784 from cve-search/dependabot/pip/jinja2-3.0.2. [PT]

* Bump jinja2 from 3.0.1 to 3.0.2. [dependabot[bot]]

  Bumps [jinja2](https://github.com/pallets/jinja) from 3.0.1 to 3.0.2.
  - [Release notes](https://github.com/pallets/jinja/releases)
  - [Changelog](https://github.com/pallets/jinja/blob/main/CHANGES.rst)
  - [Commits](https://github.com/pallets/jinja/compare/3.0.1...3.0.2)

  ---
  updated-dependencies:
  - dependency-name: jinja2
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #786 from cve-search/dependabot/pip/werkzeug-2.0.2. [PT]

* Bump werkzeug from 2.0.1 to 2.0.2. [dependabot[bot]]

  Bumps [werkzeug](https://github.com/pallets/werkzeug) from 2.0.1 to 2.0.2.
  - [Release notes](https://github.com/pallets/werkzeug/releases)
  - [Changelog](https://github.com/pallets/werkzeug/blob/main/CHANGES.rst)
  - [Commits](https://github.com/pallets/werkzeug/compare/2.0.1...2.0.2)

  ---
  updated-dependencies:
  - dependency-name: werkzeug
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #783 from cve-search/dependabot/pip/flask-2.0.2. [PT]

* Bump flask from 2.0.1 to 2.0.2. [dependabot[bot]]

  Bumps [flask](https://github.com/pallets/flask) from 2.0.1 to 2.0.2.
  - [Release notes](https://github.com/pallets/flask/releases)
  - [Changelog](https://github.com/pallets/flask/blob/main/CHANGES.rst)
  - [Commits](https://github.com/pallets/flask/compare/2.0.1...2.0.2)

  ---
  updated-dependencies:
  - dependency-name: flask
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #782 from cve-search/dependabot/pip/pytest-cov-3.0.0. [PT]

* Bump pytest-cov from 2.12.1 to 3.0.0. [dependabot[bot]]

  Bumps [pytest-cov](https://github.com/pytest-dev/pytest-cov) from 2.12.1 to 3.0.0.
  - [Release notes](https://github.com/pytest-dev/pytest-cov/releases)
  - [Changelog](https://github.com/pytest-dev/pytest-cov/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest-cov/compare/v2.12.1...v3.0.0)

  ---
  updated-dependencies:
  - dependency-name: pytest-cov
    dependency-type: direct:production
    update-type: version-update:semver-major
  ...

* Merge pull request #789 from oh2fih/master. [PT]

* Merge branch 'cve-search:master' into master. [Esa Jokinen]

* Merge pull request #785 from oh2fih/master. [PT]

* Remove IRC and XMPP from documentation (#787) [Esa Jokinen]

* Remove requirements for IRC and XMPP (#787) [Esa Jokinen]

* Remove broken feature: XMPP bot (#787) [Esa Jokinen]

* Remove broken feature: IRC bot (#787) [Esa Jokinen]

* Add "Logging: True/False" in sample config (#774) [Esa Jokinen]

* Improve logging: config & fault tolerance (#774) [Esa Jokinen]

* Merge pull request #778. [PT]

  update redoc

* Redoc update. [Paul Tikken Laptop]

* Merge pull request #777. [PT]

  req update

* Docs update. [Paul Tikken Laptop]

* Merge pull request #776. [PT]

  docs update

* Docs update. [Paul Tikken Laptop]

* Merge pull request #775. [PT]

  update requirements

* Update requirements.txt. [Paul Tikken Laptop]

* Merge pull request #771 from cve-search/dependabot/pip/tqdm-4.62.3. [PT]

  Bump tqdm from 4.62.2 to 4.62.3

* Bump tqdm from 4.62.2 to 4.62.3. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.62.2 to 4.62.3.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.62.2...v4.62.3)

  ---
  updated-dependencies:
  - dependency-name: tqdm
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #772 from cve-search/dependabot/pip/nltk-3.6.3. [PT]

  Bump nltk from 3.6.2 to 3.6.3

* Bump nltk from 3.6.2 to 3.6.3. [dependabot[bot]]

  Bumps [nltk](https://github.com/nltk/nltk) from 3.6.2 to 3.6.3.
  - [Release notes](https://github.com/nltk/nltk/releases)
  - [Changelog](https://github.com/nltk/nltk/blob/develop/ChangeLog)
  - [Commits](https://github.com/nltk/nltk/compare/3.6.2...3.6.3)

  ---
  updated-dependencies:
  - dependency-name: nltk
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #766 from oh2fih/master. [PT]

  Ajaxify searches & adjust search result reason priority

* Merge branch 'cve-search:master' into master. [Esa Jokinen]

* Merge pull request #768 from cve-search/dependabot/pip/sphinx-rtd-theme-1.0.0. [PT]

  Bump sphinx-rtd-theme from 0.5.2 to 1.0.0

* Bump sphinx-rtd-theme from 0.5.2 to 1.0.0. [dependabot[bot]]

  Bumps [sphinx-rtd-theme](https://github.com/readthedocs/sphinx_rtd_theme) from 0.5.2 to 1.0.0.
  - [Release notes](https://github.com/readthedocs/sphinx_rtd_theme/releases)
  - [Changelog](https://github.com/readthedocs/sphinx_rtd_theme/blob/master/docs/changelog.rst)
  - [Commits](https://github.com/readthedocs/sphinx_rtd_theme/compare/0.5.2...1.0.0)

  ---
  updated-dependencies:
  - dependency-name: sphinx-rtd-theme
    dependency-type: direct:development
    update-type: version-update:semver-major
  ...

* Merge pull request #769 from cve-search/dependabot/pip/sphinx-4.2.0. [PT]

  Bump sphinx from 4.1.2 to 4.2.0

* Bump sphinx from 4.1.2 to 4.2.0. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 4.1.2 to 4.2.0.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/4.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v4.1.2...v4.2.0)

  ---
  updated-dependencies:
  - dependency-name: sphinx
    dependency-type: direct:development
    update-type: version-update:semver-minor
  ...

* Fix breadcrumb for freetext search. [Esa Jokinen]

* Update search tooltip. [Esa Jokinen]

* Change freetext search path (removing '?search=') [Esa Jokinen]

* Remove unused template static_table.html (#758) [Esa Jokinen]

* Breadcrumb for freetext search (#758) [Esa Jokinen]

* Expand Ajax search to vendor browsing (#758) [Esa Jokinen]

* Merge branch 'cve-search:master' into master. [Esa Jokinen]

* Merge pull request #764 from oh2fih/master. [PT]

* Adjust search result reason priority. [Esa Jokinen]

* Show 'reason' only if exists. Fix indentation. [Esa Jokinen]

* Shared functions: better on the same file. (#758) [Esa Jokinen]

* Ajaxify freetext search (#758) [Esa Jokinen]

* Merge branch 'cve-search:master' into master. [Esa Jokinen]

* Merge pull request #762 from oh2fih/master. [PT]

* Filter validation for an authenticated user (#763) [Esa Jokinen]

* Authenticated user defaults for the filter (#763) [Esa Jokinen]

* Backend state for the auth user filter form (#763) [Esa Jokinen]

* CSS for Bootstrap v4.5.2 -> v4.6.0. [Esa Jokinen]

* Update Bootstrap v4.5.2 -> v4.6.0 (#761) [Esa Jokinen]

* Popper required by Bootstrap must be before it. [Esa Jokinen]

* Merge branch 'web-cleanup' [Esa Jokinen]

* Update clipboard.js v2.0.6 -> v2.0.8 (#761) [Esa Jokinen]

* Update Popper (?? 2019 version) -> v2.10.1 (#761) [Esa Jokinen]

* Update DataTables 1.10.22 -> 1.11.2 (#761) [Esa Jokinen]

* Remove legacy Flash (#761) [Esa Jokinen]

* Uniform style with master-page layout (#761) [Esa Jokinen]

* Remove unused HTML5 Shiv v3.6.2 (#761) [Esa Jokinen]

* Abandon IE 6-8 support. (#761) [Esa Jokinen]

* CSS for Font Awesome Free 5.13.0 -> 5.15.4 (#761) [Esa Jokinen]

* Remove unused jQuery v3.5.1 (#761) [Esa Jokinen]

* Use jQuery v3.6.0 (replacing jQuery v3.5.1) (#761) [Esa Jokinen]

* Add jQuery v3.6.0 (#761) [Esa Jokinen]

* Remove unused fonts (glyphicons-halflings) (#761) [Esa Jokinen]

* Update Font Awesome Free 5.13.0 -> 5.15.4 (#761) [Esa Jokinen]

* Enable Font Awesome Free (ref. all.min.js) (#761) [Esa Jokinen]

* Remove unused jQuery v1.11.2 (#761) [Esa Jokinen]

* Remove unreferenced template api.html (#761) [Esa Jokinen]

* Remove unreferenced template filters2.html (#761) [Esa Jokinen]

* Merge pull request #760 from oh2fih/master. [PT]

* Merge branch 'cve-search:master' into master. [Esa Jokinen]

* Merge pull request #755 from cve-search/dependabot/pip/beautifulsoup4-4.10.0. [PT]

  Bump beautifulsoup4 from 4.9.3 to 4.10.0

* Bump beautifulsoup4 from 4.9.3 to 4.10.0. [dependabot[bot]]

  Bumps [beautifulsoup4](http://www.crummy.com/software/BeautifulSoup/bs4/) from 4.9.3 to 4.10.0.

  ---
  updated-dependencies:
  - dependency-name: beautifulsoup4
    dependency-type: direct:production
    update-type: version-update:semver-minor
  ...

* Fix indentation. [Esa Jokinen]

* Rename the function to be less general. (#758) [Esa Jokinen]

* One more MountPath fix for (#759) [Esa Jokinen]

* Merge branch 'cve-search:master' into master. [oh2fih]

* Merge pull request #756 from oh2fih/master. [PT]

  Minor improvements to the filter functionality. Fixed search.

* Merge pull request #757 from DocArmoryTech/patch-1. [PT]

  Fix typo in production installation

* Fix typo in production installation. [DocArmoryTech]

  Added missing redirects `>` to the `cat` commands in the instructions for production installation

* Facilitate mounting with JS var MountPath (#759) [Esa Jokinen]

* Dynamically generate URL for mounting. [Esa Jokinen]

* These were already fixed in #728 but got reverted. [Esa Jokinen]

* Add global JS variable for MountPath (#759) [Esa Jokinen]

* Removed duplicate // from favicon URL. [Esa Jokinen]

* Beautify indentation etc. [Esa Jokinen]

* This is redundant, too. [Esa Jokinen]

* Fix freetext search form; simplified GET-redirect. [Esa Jokinen]

* /search to support both GET & POST. Fix redirect. [Esa Jokinen]

* Delete invalid cookie more aggressively. [Esa Jokinen]

* Make the "Filter" buttons behave equally. [Esa Jokinen]

* Show the filter box if a warning is displayed. [Esa Jokinen]

* Merge pull request #754 from oh2fih/master. [PT]

  Fix the server-side filter date validation

* Merge branch 'cve-search:master' into master. [oh2fih]

* Merge pull request #753 from oh2fih/master. [PT]

  Move inline JavaScript from the HTML template to static .js files

* Fix the server-side date validation. (#733) [Esa Jokinen]

* Added newline in the end of file. [Esa Jokinen]

* Move all possible inline JS to static files. [Esa Jokinen]

* Uniform indentation. [Esa Jokinen]

* Move filter related JS from template to /static. [Esa Jokinen]

* Not used anywhere; setFilters() always empty. [Esa Jokinen]

* Merge pull request #752 from P-T-I/cve-search-751. [PT]

* Dropping all collections when forced. [Paul Tikken Laptop]

* Reconfigured wsgi mount path to be configurable via the configuration settings. [Paul Tikken Laptop]

* Merge pull request #749 from P-T-I/cve-search-742. [PT]

  Web GUI filters always filtering on CVSS3 (despite CVSS2 chosen)

* Fix #742; fixed gui performing wrong CVSS filter and fixed filtering on dates which where performed on the wrong date format. [Paul Tikken Laptop]

* Merge branch 'up_master' into cve-search-742. [Paul Tikken Laptop]

* Merge pull request #748 from oh2fih/master. [PT]

  Client-side filter handling with cookies

* More responsive user interactions (#747) [Esa Jokinen]

* Client-side filter validation (#747) [Esa Jokinen]

* Better look for warning (same size when empty). [Esa Jokinen]

* Merge branch 'cve-search:master' into master. [oh2fih]

* Reduce requests to /fetch_cve_data (#747) [Esa Jokinen]

* No need for server-side logging anymore (#747) [Esa Jokinen]

* Move filter handling client-side (#747) [Esa Jokinen]

* Fixed bug where datestrings where not handled correctly. [Paul Tikken Laptop]

* Merge pull request #746. [PT]

  UX enhancements related to the previous fixes on bug #733

* UX: hilight active drop-down menu options. (#733) [Esa Jokinen]

* UX: replace JS alerts with inline warnings (#733) [Esa Jokinen]

* Update installation.rst. [PT]

* Merge pull request #743 from oh2fih/master. [PT]

  Added backend filter validation and pre-filling of the filter form data

* Beautify console errors & reduce verbosity. (#733) [Esa Jokinen]

* Update filter form with the backend state. (#733) [Esa Jokinen]

* Fix a typo; making 'equals' & 'below' work (#733) [Esa Jokinen]

* Make frontend aware of the backend state (#733) [Esa Jokinen]

* Backend filter validation for /set_filter (#733) [Esa Jokinen]

* Merge pull request #744 from DocArmoryTech/wsgi-doc. [PT]

  UWSGI documentation update

* Fixed rst reference to Config section. [DocArmoryTech]

* Added note to highlight end of standard install. [DocArmoryTech]

  Added note to highlight end of standard install and direct the reader on to the Configuration section (hoping to avoid people trying to perform both installations

* Renamed 'basic' to 'standard' installation. [DocArmoryTech]

* Update webgui.rst. [DocArmoryTech]

  Decomposed the "starting the webserver" section into two parts one for a standard installation, and one for a production installation that covers setup of uwsgi and nginx

* Update webgui.rst. [DocArmoryTech]

* Removed UWSGI and NGINX setup. [DocArmoryTech]

  Removed UWSGI and NGINX setup with the intention of replacing it under the webgui section of the docs

* Corrected type in virtualenv. [DocArmoryTech]

* Added virtualenv parameter. [DocArmoryTech]

  Added a `virtualenv` parameter to tally with that specified in the docs

* Copied mongo-db install to Prod. Install. [DocArmoryTech]

  Copied the instructions for installing mongodb to the "Production Installation" section

* Updated docs to use requirements.prod file. [DocArmoryTech]

* Create requirements.prod. [DocArmoryTech]

* Update installation.rst. [DocArmoryTech]

* Fixed formatting of new section. [DocArmoryTech]

  Fixed md formatting of new "Production Installation"  section

* Create nginx.conf.sample. [DocArmoryTech]

* Update installation.rst. [DocArmoryTech]

* Merge pull request #741 from P-T-I/cleanup. [PT]

  query published date

* Fixed bug where datestrings posted to the api/query endpoint where not handled correctly. [Paul Tikken Laptop]

* Merge pull request #738 from P-T-I/plugin_rewrite. [PT]

  Plugin rewrite

* Documentation update and first release for Cve-Search plugin. [Paul Tikken Laptop]

* Rebase merge. [Paul Tikken Laptop]

* Merge pull request #737 from P-T-I/cve-search-709. [PT]

  /api/dbInfo missing in the new API

* Restructure dbinfo in documentation. [Paul Tikken Laptop]

* Merge pull request #736 from P-T-I/cve-search-734. [PT]

  Issues using the REST API

* Added cvssVersion header. [Paul Tikken Laptop]

* Updated requirements and fixed headers with underscore no longer being processed by the REST API. [Paul Tikken Laptop]

* Merge pull request #732 from P-T-I/cve-search-714. [PT]

  Support for MongoDB 5.0

* Black formatting. [Paul Tikken Laptop]

* Rebase. [Paul Tikken Laptop]

* Merge pull request #728 from DocArmoryTech/mounty. [PT]

  Dynamically generate all URLs to facilitate mounting

* Small error with cwe breadcrumb. [Paul Tikken Laptop]

* Merge branch 'mounty' of https://github.com/DocArmoryTech/cve-search into mounty. [dotsie]

* Updated fixed to masterLogin. [DocArmoryTech]

  Reverted changes made to masterLogin function to make use of the *local* (and not absent) `verifyPass` function.

* Version change for rebase. [DocArmoryTech]

* Corrected version. [DocArmoryTech]

* Update VERSION. [DocArmoryTech]

* Update wsgi.ini.sample. [DocArmoryTech]

* Fixed path of wsgi-file. [DocArmoryTech]

* Removed beforeSend hook. [dotsie]

* Prefix XHR urls with url_for. [dotsie]

* Fixed typo in chaneg_pass url. [dotsie]

* Moved XHR js functions to admin template. [dotsie]

* Modified URL generation in stand UI. [dotsie]

* Fixed urls in admin or full webui. [dotsie]

* Fixed db mgmt admin scripts ref to non-existent function. [dotsie]

  db_mgmt_admin.py attempted to make use of the mongodb plugin's verifyPass function.

  Assuming a refactoring oversight, and changing the function call to verifyUser(user, pass)

* Merge branch 'mounty' of https://github.com/DocArmoryTech/cve-search into mounty. [dotsie]

* Create wsgi.ini.sample. [DocArmoryTech]

  A minimal example of a uwsgi ini that runs cve-search listening on a socket

* Removed leading slash from constructed breadcrumb urls. [dotsie]

  - Modified dynamic list constructors so as to not return a leading `/` in generated URLs
   - Modified the loop body that generates the page breadcrumb so as to include the url_for('home.index')

  todo:
   - modify admin 'views'
   - admin/account testing

* Dynamically generated urls to static resources for app mounting /_get_plugins. [dotsie]

  In order to faciliate 'mounting' of cve-search as a web app, or alteration of the application root:

   - Modified the 'hard coded' urls to static resources (css, imgs, js) to use the url_for() function to generate urls dynamically
   - Added a new `<script>` in the `<head>` of `web/templates/layouts/master-page.html`
     - moved the ~search~ `redirect()` function from `web/static/js/custom/scripts.js` to a new `<script>` in the _master_ layout template
     - modified the `redirect()` function to use `url_for()` when generating urls and redirecting
     - configured ajax to prepend the web_root to XHR requets using the `beforeSend` hook

  Todo:
   - Breadcrumbs are broken
   - Admin functions need testing

* Update wsgi.ini.sample. [DocArmoryTech]

* Fixed path of wsgi-file. [DocArmoryTech]

* Removed beforeSend hook. [dotsie]

* Prefix XHR urls with url_for. [dotsie]

* Fixed typo in chaneg_pass url. [dotsie]

* Moved XHR js functions to admin template. [dotsie]

* Modified URL generation in stand UI. [dotsie]

* Fixed urls in admin or full webui. [dotsie]

* Create wsgi.ini.sample. [DocArmoryTech]

  A minimal example of a uwsgi ini that runs cve-search listening on a socket

* Removed leading slash from constructed breadcrumb urls. [dotsie]

  - Modified dynamic list constructors so as to not return a leading `/` in generated URLs
   - Modified the loop body that generates the page breadcrumb so as to include the url_for('home.index')

  todo:
   - modify admin 'views'
   - admin/account testing

* Dynamically generated urls to static resources for app mounting /_get_plugins. [dotsie]

  In order to faciliate 'mounting' of cve-search as a web app, or alteration of the application root:

   - Modified the 'hard coded' urls to static resources (css, imgs, js) to use the url_for() function to generate urls dynamically
   - Added a new `<script>` in the `<head>` of `web/templates/layouts/master-page.html`
     - moved the ~search~ `redirect()` function from `web/static/js/custom/scripts.js` to a new `<script>` in the _master_ layout template
     - modified the `redirect()` function to use `url_for()` when generating urls and redirecting
     - configured ajax to prepend the web_root to XHR requets using the `beforeSend` hook

  Todo:
   - Breadcrumbs are broken
   - Admin functions need testing

* Black formatting. [Paul Tikken Laptop]

* Change is not backwards compatible with earlier create indexes in mongodb; so rebuild is needed. [Paul Tikken Laptop]

* Removed weights from indexes for mongodb 5.0 compatibility and black formatting. [Paul Tikken Laptop]

* Merge pull request #731 from P-T-I/cve-search-680. [PT]

  db update throws error message after creating user

* Fixed errors when inserting a user into the database. [Paul Tikken Laptop]

* Black formatting and requirement added. [Paul Tikken Laptop]

* Merge master. [Paul Tikken Laptop]

* Merge pull request #730 from P-T-I/cve-search-712. [PT]

  Update source to capec3.5

* Fix #712; updated to capec3.5 and upped schema version. [Paul Tikken Laptop]

* Merge pull request #729 from P-T-I/master. [PT]

  updated docs and updated requirements

* Updated docs and updated requirements. [Paul Tikken Laptop]

* Merge pull request #720 from cve-search/dependabot/pip/requests-2.26.0. [PT]

* Bump requests from 2.25.1 to 2.26.0. [dependabot[bot]]

  Bumps [requests](https://github.com/psf/requests) from 2.25.1 to 2.26.0.
  - [Release notes](https://github.com/psf/requests/releases)
  - [Changelog](https://github.com/psf/requests/blob/master/HISTORY.md)
  - [Commits](https://github.com/psf/requests/compare/v2.25.1...v2.26.0)

  ---
  updated-dependencies:
  - dependency-name: requests
    dependency-type: direct:production
    update-type: version-update:semver-minor
  ...

* Merge pull request #715 from cve-search/dependabot/pip/sphinx-4.0.3. [PT]

* Bump sphinx from 4.0.2 to 4.0.3. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 4.0.2 to 4.0.3.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/4.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v4.0.2...v4.0.3)

  ---
  updated-dependencies:
  - dependency-name: sphinx
    dependency-type: direct:development
    update-type: version-update:semver-patch
  ...

* Merge pull request #716 from cve-search/dependabot/pip/flask-jwt-extended-4.2.3. [PT]

* Bump flask-jwt-extended from 4.2.1 to 4.2.3. [dependabot[bot]]

  Bumps [flask-jwt-extended](https://github.com/vimalloc/flask-jwt-extended) from 4.2.1 to 4.2.3.
  - [Release notes](https://github.com/vimalloc/flask-jwt-extended/releases)
  - [Commits](https://github.com/vimalloc/flask-jwt-extended/compare/4.2.1...4.2.3)

  ---
  updated-dependencies:
  - dependency-name: flask-jwt-extended
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #717 from cve-search/dependabot/pip/tqdm-4.61.2. [PT]

* Bump tqdm from 4.61.1 to 4.61.2. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.61.1 to 4.61.2.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.61.1...v4.61.2)

  ---
  updated-dependencies:
  - dependency-name: tqdm
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #707 from cve-search/dependabot/pip/tqdm-4.61.1. [PT]

* Bump tqdm from 4.61.0 to 4.61.1. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.61.0 to 4.61.1.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.61.0...v4.61.1)

  ---
  updated-dependencies:
  - dependency-name: tqdm
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #705 from cve-search/dependabot/pip/pytest-cov-2.12.1. [PT]

* Bump pytest-cov from 2.12.0 to 2.12.1. [dependabot[bot]]

  Bumps [pytest-cov](https://github.com/pytest-dev/pytest-cov) from 2.12.0 to 2.12.1.
  - [Release notes](https://github.com/pytest-dev/pytest-cov/releases)
  - [Changelog](https://github.com/pytest-dev/pytest-cov/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest-cov/compare/v2.12.0...v2.12.1)

  ---
  updated-dependencies:
  - dependency-name: pytest-cov
    dependency-type: direct:production
    update-type: version-update:semver-patch
  ...

* Merge pull request #699 from cve-search/dependabot/pip/tqdm-4.61.0. [PT]

  Bump tqdm from 4.60.0 to 4.61.0

* Bump tqdm from 4.60.0 to 4.61.0. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.60.0 to 4.61.0.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.60.0...v4.61.0)

* Merge pull request #703 from cve-search/dependabot/pip/flask-wtf-0.15.1. [PT]

* Bump flask-wtf from 0.14.3 to 0.15.1. [dependabot[bot]]

  Bumps [flask-wtf](https://github.com/wtforms/flask-wtf) from 0.14.3 to 0.15.1.
  - [Release notes](https://github.com/wtforms/flask-wtf/releases)
  - [Changelog](https://github.com/wtforms/flask-wtf/blob/main/docs/changes.rst)
  - [Commits](https://github.com/wtforms/flask-wtf/compare/0.14.3...v0.15.1)

* Merge pull request #702 from hashier/fix/dependencies. [PT]

* Fix(dependencies): dowgrade flask. [Christopher Loessl]

  because flask-restx is not yet compatible

* Merge pull request #697 from P-T-I/cve-search-690. [PT]

  fixed double entries in the CWE description (and also notic…

* Fix #690; fixed double entries in the CWE description (and also noticed that the wrong description is in the CWE description) [Paul Tikken Laptop]

* Merge pull request #696 from P-T-I/cve-search-679. [PT]

  Let data tables respond to PageLength setting

* Fix #679; Let data tables respond to PageLength setting in configuration.ini. [Paul Tikken Laptop]

* Merge pull request #695 from P-T-I/master. [PT]

  Update requirements files

* Updated requirements.txt. [Paul Tikken Laptop]

* Merge branch 'up_master' [Paul Tikken Laptop]

* Merge pull request #691 from cve-search/dependabot/pip/sphinx-4.0.2. [PT]

  Bump sphinx from 3.5.4 to 4.0.2

* Bump sphinx from 3.5.4 to 4.0.2. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.5.4 to 4.0.2.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/4.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.5.4...v4.0.2)

* Updated requirements.txt. [Paul Tikken Laptop]

* Updated requirements.txt. [Paul Tikken Laptop]

* Merge pull request #678 from cve-search/dependabot/pip/pytest-6.2.4. [PT]

* Bump pytest from 6.2.3 to 6.2.4. [dependabot[bot]]

  Bumps [pytest](https://github.com/pytest-dev/pytest) from 6.2.3 to 6.2.4.
  - [Release notes](https://github.com/pytest-dev/pytest/releases)
  - [Changelog](https://github.com/pytest-dev/pytest/blob/main/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest/compare/6.2.3...6.2.4)

* Merge pull request #677 from cve-search/dependabot/pip/pymongo-3.11.4. [PT]

* Bump pymongo from 3.11.3 to 3.11.4. [dependabot[bot]]

  Bumps [pymongo](https://github.com/mongodb/mongo-python-driver) from 3.11.3 to 3.11.4.
  - [Release notes](https://github.com/mongodb/mongo-python-driver/releases)
  - [Changelog](https://github.com/mongodb/mongo-python-driver/blob/3.11.4/doc/changelog.rst)
  - [Commits](https://github.com/mongodb/mongo-python-driver/compare/3.11.3...3.11.4)

* Merge branch 'up_master' into plugin_rewrite. [Paul Tikken Laptop]

* Merge pull request #676 from cve-search/dependabot/pip/flask-jwt-extended-4.2.0. [PT]

  Bump flask-jwt-extended from 4.1.0 to 4.2.0

* Bump flask-jwt-extended from 4.1.0 to 4.2.0. [dependabot[bot]]

  Bumps [flask-jwt-extended](https://github.com/vimalloc/flask-jwt-extended) from 4.1.0 to 4.2.0.
  - [Release notes](https://github.com/vimalloc/flask-jwt-extended/releases)
  - [Commits](https://github.com/vimalloc/flask-jwt-extended/compare/4.1.0...4.2.0)

* Merge remote-tracking branch 'origin/plugin_rewrite' into plugin_rewrite. [Paul Tikken Laptop]

  # Conflicts:
  #	web/VERSION

* Merge up_master. [Paul Tikken Laptop]

* Merge up_master. [Paul Tikken Laptop]

* Merge pull request #673 from P-T-I/redoc_update. [PT]

  redoc update

* Redoc update. [Paul Tikken Laptop]

* Merge pull request #671 from M0dEx/master. [PT]

  Search in 'vendors' and 'products' fields

* Search in 'vendors' and 'products' fields - earching using only fulltext searches misses a lot of obvious matches (search for "trendmicro" or "trend micro" returns a lot less CVEs than it should (<150, when there are 300+ CVEs for Trend Micro) [M0dEx]

* Merge pull request #668 from M0dEx/master. [PT]

* Convert WORKER_SIZE from ENV to int as it can cause issues when not converted (in CVE-Search-Docker, for example) [M0dEx]

* Working on flask-plugins. [Paul Tikken Laptop]

* Working on flask-plugins. [Paul Tikken Laptop]

* Refactored the CVE page. [Paul Tikken Laptop]

* Cleanup old plugin framework. [Paul Tikken Laptop]

* Cleanup old plugin framework. [Paul Tikken Laptop]

* Merge branch 'up_master' into plugin_rewrite. [Paul Tikken Laptop]

* Merge. [Paul Tikken Laptop]

* Working on new plugin framework. [Paul Tikken Laptop]


## v4.1.0 (2021-04-24)

### New

* [db_mgmt_json] first version of importing NVD CVE from the new JSON format. [Alexandre Dulaunoy]

  - new import script (db_mgmt_json) added to parse the JSON entries and import in MongoDB
  - Goal was to map existing data found in the old XML format from the new NVD JSON format
  - cpe2.2 is now discarded (cpe2.3 should be the default in cve-search)
  - CWE contains additional type of fields from the NVD which need to be fixed
  - ranking is currently disabled (WiP to add it back in minimal API later)

### Changes

* [version] v4.1.0 released. [Alexandre Dulaunoy]

* [copyright] add Paul as co-author. [Alexandre Dulaunoy]

* [travis] fix to use JSON NVD source + removed unsupported Python version. [Alexandre Dulaunoy]

* [doc] reference to the ChangeLog updated. [Alexandre Dulaunoy]

* [source] default to nvd cve 1.1. [Alexandre Dulaunoy]

* [cve source] now officially use nvd 1.1 version. [Alexandre Dulaunoy]

* [config] download CVE JSON feed in version 1.1. [Alexandre Dulaunoy]

* [DatabaseLayer] access field missing added - Fix #404. [Alexandre Dulaunoy]

* [DatabaseLayer] add missing impact field in the update. [Alexandre Dulaunoy]

  Thanks to the good report in issue #403.

* [cpe/bulkUpdate] use format instead of concat. [Alexandre Dulaunoy]

* [db] all regex queries are now case insensitive. [Alexandre Dulaunoy]

* [web] template vulnerable_product and assigner is a default field. [Alexandre Dulaunoy]

* [sources] revert back CAPEC XML source (parser is broken with recent version) [Alexandre Dulaunoy]

* [db_mgmt_json] use of format. [Alexandre Dulaunoy]

* [cwe] CWE import fixed using pull-request #353. [Alexandre Dulaunoy]

  This should fix issue #252 #348

  Thanks to @DocArmoryTech @FafnerKeyZee

* [cveforCPE] fix to use the new result part. [Alexandre Dulaunoy]

  Fix #382

* [cpe browser] redis - quick fix for browser to work with recent cpe version. [Alexandre Dulaunoy]

* [search] use format as output instead of concatenation. [Alexandre Dulaunoy]

* [DatabaseLayer] cleanup. [Alexandre Dulaunoy]

* [search] fix due to the recent change of the library interface. [Alexandre Dulaunoy]

* [cpe search] fixed for the JSON output. [Alexandre Dulaunoy]

* [doc] Python 3.6 required. [Alexandre Dulaunoy]

* [db_mgmt_json] improve the parsing of the vulnerable_configuration tree format. [Alexandre Dulaunoy]

  - children entries are now taken into account
  - a new field is added to add the non_vulnerable_configuration

  This should fix a very old bug in XML where non vulnerable configuration
  were imported into the vulnerable_configuration.

  And it should also fix the issue #373

* [db_mgmt_json] force option to update the current JSON of NVD. [Alexandre Dulaunoy]

* [db_mgmt_json] CVSSv2 vector is now imported. [Alexandre Dulaunoy]

* [search_cpe] references added in output and csv output added. [Alexandre Dulaunoy]

* [db_mgmt_json] minor fixes (format) [Alexandre Dulaunoy]

* [doc] README updated with JSON feed download. [Alexandre Dulaunoy]

* [source] fix CPE v2.3 url. [Alexandre Dulaunoy]

* [doc] add new MISP modules using cve-search. [Alexandre Dulaunoy]

* [doc] Added initial import indication. [Steve Clement]

### Fix

* [doc] fix the default link of the public cvepremium.circl.lu. [Alexandre Dulaunoy]

* [view/capec] Non existing CAPEC value was not properly handled. [Alexandre Dulaunoy]

  Fix #648

* [json import] ASSIGNER not always present (required) in NVD json feed. [Alexandre Dulaunoy]

  Fix #650

* [db_mgmt_json] if cpe_name is missing from original CPE then use default cpe23 URI. [Alexandre Dulaunoy]

* [minimal] link result is now using the proper cve result key. [Alexandre Dulaunoy]

* Display the correct number of elements in cves. [Alexandre Dulaunoy]

### Other

* Merge pull request #664 from P-T-I/cve-search-659. [PT]

  fix #cve-search-659; wrong date format disables effective sorting on …

* Fix #cve-search-659; wrong date format disables effective sorting on table + inserted cvss3 score to vendor search table. [Paul Tikken Laptop]

* Merge pull request #663 from P-T-I/cve-search-660. [PT]

  fix #cve-search-660; fixed the back to top button covering the datata…

* Fix #cve-search-660; fixed the back to top button covering the datatables buttons. [Paul Tikken Laptop]

* Merge pull request #662 from P-T-I/master. [PT]

  Proxies fix

* Proxies fix. [Paul Tikken Laptop]

* Proxies fix. [Paul Tikken Laptop]

* Merge pull request #661 from P-T-I/master. [PT]

  proxies fix

* Proxies fix. [Paul Tikken Laptop]

* Merge pull request #657 from P-T-I/cve-search-586. [PT]

  Fix #cve-search-586; created possibility to set download worker size …

* Merge branch 'master' into cve-search-586. [Paul Tikken Laptop]

* Merge pull request #615 from EXXETA/downloadHandlerProxy. [PT]

  Use http proxy in download handler

* Move proxy setting to a more central place (get_session) [Justin Kromlinger]

* Move configuration to a class variable and import statement to the top of the file. [Justin Kromlinger]

* Use http proxy in download handler. [Justin Kromlinger]

* Fix #cve-search-586; created possibility to set download worker size via environment variable. [Paul Tikken Laptop]

* Merge pull request #656 from FafnerKeyZee/patch-2. [Alexandre Dulaunoy]

  dirty patch for #651

* Update Sources_process.py. [Fafner [_KeyZee_]]

* Update Sources_process.py. [Fafner [_KeyZee_]]

* Update Sources_process.py. [Fafner [_KeyZee_]]

  Yeah it's a dirty fix, but it does the job for the moment.

* Merge pull request #644 from EXXETA/vendor-search. [Alexandre Dulaunoy]

  Added endpoints to search for the CPE fields vendor, product and version

* Added endpoints to search for the CPE fields vendor, product and version. [weigeltj]

* Merge pull request #647 from cve-search/dependabot/pip/nltk-3.6.2. [PT]

* Bump nltk from 3.6.1 to 3.6.2. [dependabot[bot]]

  Bumps [nltk](https://github.com/nltk/nltk) from 3.6.1 to 3.6.2.
  - [Release notes](https://github.com/nltk/nltk/releases)
  - [Changelog](https://github.com/nltk/nltk/blob/develop/ChangeLog)
  - [Commits](https://github.com/nltk/nltk/compare/3.6.1...3.6.2)

* Merge pull request #643 from cve-search/dependabot/pip/sphinx-3.5.4. [PT]

* Bump sphinx from 3.5.3 to 3.5.4. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.5.3 to 3.5.4.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/4.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/commits/v3.5.4)

* Merge pull request #642 from cve-search/dependabot/pip/nltk-3.6.1. [PT]

  Bump nltk from 3.5 to 3.6.1

* Bump nltk from 3.5 to 3.6.1. [dependabot[bot]]

  Bumps [nltk](https://github.com/nltk/nltk) from 3.5 to 3.6.1.
  - [Release notes](https://github.com/nltk/nltk/releases)
  - [Changelog](https://github.com/nltk/nltk/blob/develop/ChangeLog)
  - [Commits](https://github.com/nltk/nltk/compare/3.5...3.6.1)

* Merge pull request #641 from P-T-I/cve-search-625. [PT]

  update to cwe4.4

* Update to cwe4.4. [Paul Tikken Laptop]

* Merge pull request #640 from P-T-I/new_redoc. [PT]

  New redoc version added

* New redoc version added. [Paul Tikken Laptop]

* Merge pull request #639 from P-T-I/cve-search-612. [PT]

  Cve search 612

* Version bump. [Paul Tikken Laptop]

* Merge branch 'master' into cve-search-612. [Paul Tikken Laptop]

* Merge pull request #635 from cve-search/dependabot/pip/tqdm-4.60.0. [PT]

  Bump tqdm from 4.59.0 to 4.60.0

* Bump tqdm from 4.59.0 to 4.60.0. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.59.0 to 4.60.0.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.59.0...v4.60.0)

* Merge pull request #634 from cve-search/dependabot/pip/sphinx-rtd-theme-0.5.2. [PT]

  Bump sphinx-rtd-theme from 0.5.1 to 0.5.2

* Bump sphinx-rtd-theme from 0.5.1 to 0.5.2. [dependabot[bot]]

  Bumps [sphinx-rtd-theme](https://github.com/readthedocs/sphinx_rtd_theme) from 0.5.1 to 0.5.2.
  - [Release notes](https://github.com/readthedocs/sphinx_rtd_theme/releases)
  - [Changelog](https://github.com/readthedocs/sphinx_rtd_theme/blob/master/docs/changelog.rst)
  - [Commits](https://github.com/readthedocs/sphinx_rtd_theme/compare/0.5.1...0.5.2)

* Merge pull request #632 from cve-search/dependabot/pip/pytest-6.2.3. [PT]

* Bump pytest from 6.2.2 to 6.2.3. [dependabot[bot]]

  Bumps [pytest](https://github.com/pytest-dev/pytest) from 6.2.2 to 6.2.3.
  - [Release notes](https://github.com/pytest-dev/pytest/releases)
  - [Changelog](https://github.com/pytest-dev/pytest/blob/main/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest/compare/6.2.2...6.2.3)

* Merge pull request #631 from cve-search/dependabot/pip/flask-restx-0.3.0. [PT]

  Bump flask-restx from 0.2.0 to 0.3.0

* Bump flask-restx from 0.2.0 to 0.3.0. [dependabot[bot]]

  Bumps [flask-restx](https://github.com/python-restx/flask-restx) from 0.2.0 to 0.3.0.
  - [Release notes](https://github.com/python-restx/flask-restx/releases)
  - [Changelog](https://github.com/python-restx/flask-restx/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/python-restx/flask-restx/compare/0.2.0...0.3.0)

* Create codeql-analysis.yml. [PT]

* Merge pull request #630 from oh2fih/patch-1. [PT]

  Correct installation order

* Correct installation order. [oh2fih]

  Because `python3` & `python3-pip` are part of `requirements.system`, the system requirements must be installed before installing CVE-Search and its Python dependencies.

* Merge pull request #629 from jorgectf/fix-regex-injection. [PT]

* Fix Regular Expression injection. [jorgectf]

* Merge pull request #628 from cve-search/dependabot/pip/sphinx-3.5.3. [PT]

* Bump sphinx from 3.5.2 to 3.5.3. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.5.2 to 3.5.3.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/3.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/commits)

* Merge pull request #627 from cve-search/dependabot/pip/docs/source/jinja2-2.11.3. [PT]

  Bump jinja2 from 2.11.2 to 2.11.3 in /docs/source

* Bump jinja2 from 2.11.2 to 2.11.3 in /docs/source. [dependabot[bot]]

  Bumps [jinja2](https://github.com/pallets/jinja) from 2.11.2 to 2.11.3.
  - [Release notes](https://github.com/pallets/jinja/releases)
  - [Changelog](https://github.com/pallets/jinja/blob/master/CHANGES.rst)
  - [Commits](https://github.com/pallets/jinja/compare/2.11.2...2.11.3)

* Fix #612; add min-length attribute to search input box. [Paul Tikken Laptop]

* Merge pull request #624 from P-T-I/cve-search-622. [PT]

  fix #622; skip processing files when file failes to download...

* Fix #622; skip processing files when file failes to download... [Paul Tikken Laptop]

* Merge pull request #621 from cve-search/dependabot/pip/flask-jwt-extended-4.1.0. [PT]

* Bump flask-jwt-extended from 4.0.2 to 4.1.0. [dependabot[bot]]

  Bumps [flask-jwt-extended](https://github.com/vimalloc/flask-jwt-extended) from 4.0.2 to 4.1.0.
  - [Release notes](https://github.com/vimalloc/flask-jwt-extended/releases)
  - [Commits](https://github.com/vimalloc/flask-jwt-extended/compare/4.0.2...4.1.0)

* Merge pull request #619 from cve-search/dependabot/pip/tqdm-4.59.0. [PT]

* Bump tqdm from 4.58.0 to 4.59.0. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.58.0 to 4.59.0.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.58.0...v4.59.0)

* Merge pull request #620 from cve-search/dependabot/pip/sphinx-3.5.2. [PT]

* Bump sphinx from 3.5.1 to 3.5.2. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.5.1 to 3.5.2.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/3.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.5.1...v3.5.2)

* Merge pull request #618 from EXXETA/cpeBrowseAPI. [PT]

  Provide /browse endpoint to list product CPEs

* Fix field description. [Justin Kromlinger]

* Provide /browse endpoint to list product CPEs. [Justin Kromlinger]

  The vendor isn't really required here, but it fits the current API style
  and represents the same functionality as the webinterface.

* Merge pull request #616 from cve-search/dependabot/pip/ijson-3.1.4. [PT]

  Bump ijson from 3.1.3 to 3.1.4

* Bump ijson from 3.1.3 to 3.1.4. [dependabot[bot]]

  Bumps [ijson](https://github.com/ICRAR/ijson) from 3.1.3 to 3.1.4.
  - [Release notes](https://github.com/ICRAR/ijson/releases)
  - [Changelog](https://github.com/ICRAR/ijson/blob/master/CHANGELOG.md)
  - [Commits](https://github.com/ICRAR/ijson/compare/v3.1.3...v3.1.4)

* Merge pull request #614 from cve-search/dependabot/pip/tqdm-4.58.0. [PT]

* Bump tqdm from 4.57.0 to 4.58.0. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.57.0 to 4.58.0.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.57.0...v4.58.0)

* Merge pull request #613 from RoccovanAsselt/display_help. [PT]

* Print_help if no parameters. [Rocco van Asselt]

* Merge pull request #610 from cve-search/dependabot/pip/tqdm-4.57.0. [PT]

  Bump tqdm from 4.56.2 to 4.57.0

* Bump tqdm from 4.56.2 to 4.57.0. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.56.2 to 4.57.0.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.56.2...v4.57.0)

* Merge pull request #609 from cve-search/dependabot/pip/sphinx-3.5.1. [PT]

* Bump sphinx from 3.5.0 to 3.5.1. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.5.0 to 3.5.1.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/3.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.5.0...v3.5.1)

* Merge pull request #608 from P-T-I/cve-search-607. [PT]

  fix #607; updated the renamed jwt functions

* Fix #607; updated the renamed jwt functions. [Paul Tikken Laptop]

* Merge pull request #606 from cve-search/dependabot/pip/sphinx-3.5.0. [PT]

* Bump sphinx from 3.4.3 to 3.5.0. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.4.3 to 3.5.0.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/3.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.4.3...v3.5.0)

* Merge pull request #605 from cve-search/dependabot/pip/flask-jwt-extended-4.0.2. [PT]

* Bump flask-jwt-extended from 3.25.0 to 4.0.2. [dependabot[bot]]

  Bumps [flask-jwt-extended](https://github.com/vimalloc/flask-jwt-extended) from 3.25.0 to 4.0.2.
  - [Release notes](https://github.com/vimalloc/flask-jwt-extended/releases)
  - [Commits](https://github.com/vimalloc/flask-jwt-extended/compare/3.25.0...4.0.2)

* Merge pull request #603 from cve-search/dependabot/pip/tqdm-4.56.2. [PT]

* Bump tqdm from 4.56.1 to 4.56.2. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.56.1 to 4.56.2.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.56.1...v4.56.2)

* Merge pull request #602 from cve-search/dependabot/pip/tqdm-4.56.1. [PT]

* Bump tqdm from 4.56.0 to 4.56.1. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.56.0 to 4.56.1.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.56.0...v4.56.1)

* Merge pull request #601 from cve-search/dependabot/pip/jsonpickle-2.0.0. [PT]

* Bump jsonpickle from 1.5.1 to 2.0.0. [dependabot[bot]]

  Bumps [jsonpickle](https://github.com/jsonpickle/jsonpickle) from 1.5.1 to 2.0.0.
  - [Release notes](https://github.com/jsonpickle/jsonpickle/releases)
  - [Changelog](https://github.com/jsonpickle/jsonpickle/blob/master/CHANGES.rst)
  - [Commits](https://github.com/jsonpickle/jsonpickle/compare/v1.5.1...v2.0.0)

* Merge pull request #600 from cve-search/dependabot/pip/pymongo-3.11.3. [PT]

* Bump pymongo from 3.11.2 to 3.11.3. [dependabot[bot]]

  Bumps [pymongo](https://github.com/mongodb/mongo-python-driver) from 3.11.2 to 3.11.3.
  - [Release notes](https://github.com/mongodb/mongo-python-driver/releases)
  - [Changelog](https://github.com/mongodb/mongo-python-driver/blob/3.11.3/doc/changelog.rst)
  - [Commits](https://github.com/mongodb/mongo-python-driver/compare/3.11.2...3.11.3)

* Merge pull request #599 from cve-search/dependabot/pip/jsonpickle-1.5.1. [PT]

  Bump jsonpickle from 1.5.0 to 1.5.1

* Bump jsonpickle from 1.5.0 to 1.5.1. [dependabot[bot]]

  Bumps [jsonpickle](https://github.com/jsonpickle/jsonpickle) from 1.5.0 to 1.5.1.
  - [Release notes](https://github.com/jsonpickle/jsonpickle/releases)
  - [Changelog](https://github.com/jsonpickle/jsonpickle/blob/master/CHANGES.rst)
  - [Commits](https://github.com/jsonpickle/jsonpickle/compare/v1.5.0...v1.5.1)

* Merge pull request #598 from cve-search/dependabot/pip/jinja2-2.11.3. [PT]

  Bump jinja2 from 2.11.2 to 2.11.3

* Bump jinja2 from 2.11.2 to 2.11.3. [dependabot[bot]]

  Bumps [jinja2](https://github.com/pallets/jinja) from 2.11.2 to 2.11.3.
  - [Release notes](https://github.com/pallets/jinja/releases)
  - [Changelog](https://github.com/pallets/jinja/blob/master/CHANGES.rst)
  - [Commits](https://github.com/pallets/jinja/compare/2.11.2...2.11.3)

* Merge pull request #596 from cve-search/dependabot/pip/pytest-6.2.2. [PT]

  Bump pytest from 6.2.1 to 6.2.2

* Bump pytest from 6.2.1 to 6.2.2. [dependabot[bot]]

  Bumps [pytest](https://github.com/pytest-dev/pytest) from 6.2.1 to 6.2.2.
  - [Release notes](https://github.com/pytest-dev/pytest/releases)
  - [Changelog](https://github.com/pytest-dev/pytest/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest/compare/6.2.1...6.2.2)

* Merge pull request #593 from cve-search/dependabot/pip/gevent-21.1.2. [PT]

  Bump gevent from 21.1.1 to 21.1.2

* Bump gevent from 21.1.1 to 21.1.2. [dependabot[bot]]

  Bumps [gevent](https://github.com/gevent/gevent) from 21.1.1 to 21.1.2.
  - [Release notes](https://github.com/gevent/gevent/releases)
  - [Changelog](https://github.com/gevent/gevent/blob/master/docs/changelog_pre.rst)
  - [Commits](https://github.com/gevent/gevent/compare/21.1.1...21.1.2)

* Merge pull request #594 from cve-search/dependabot/pip/pytest-cov-2.11.1. [PT]

  Bump pytest-cov from 2.11.0 to 2.11.1

* Bump pytest-cov from 2.11.0 to 2.11.1. [dependabot[bot]]

  Bumps [pytest-cov](https://github.com/pytest-dev/pytest-cov) from 2.11.0 to 2.11.1.
  - [Release notes](https://github.com/pytest-dev/pytest-cov/releases)
  - [Changelog](https://github.com/pytest-dev/pytest-cov/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest-cov/compare/v2.11.0...v2.11.1)

* Merge pull request #592 from cve-search/dependabot/pip/gevent-21.1.1. [PT]

  Bump gevent from 21.1.0 to 21.1.1

* Bump gevent from 21.1.0 to 21.1.1. [dependabot[bot]]

  Bumps [gevent](https://github.com/gevent/gevent) from 21.1.0 to 21.1.1.
  - [Release notes](https://github.com/gevent/gevent/releases)
  - [Changelog](https://github.com/gevent/gevent/blob/master/docs/changelog_pre.rst)
  - [Commits](https://github.com/gevent/gevent/compare/21.1.0...21.1.1)

* Merge pull request #591 from P-T-I/cve-search-587. [PT]

  fix #587; allowing local files to be set in the sources.ini file via …

* Fix #587; allowing local files to be set in the sources.ini file via a file:///PATH/TO/FILE.json; this is applicable for all different sources; which creates the possibility to update cve-search completely offline. [Paul Tikken Laptop]

* Merge pull request #590 from cve-search/dependabot/pip/gevent-21.1.0. [PT]

  Bump gevent from 20.12.1 to 21.1.0

* Bump gevent from 20.12.1 to 21.1.0. [dependabot[bot]]

  Bumps [gevent](https://github.com/gevent/gevent) from 20.12.1 to 21.1.0.
  - [Release notes](https://github.com/gevent/gevent/releases)
  - [Changelog](https://github.com/gevent/gevent/blob/master/docs/changelog_pre.rst)
  - [Commits](https://github.com/gevent/gevent/compare/20.12.1...21.1.0)

* Merge pull request #589 from cve-search/dependabot/pip/jsonpickle-1.5.0. [PT]

  Bump jsonpickle from 1.4.2 to 1.5.0

* Bump jsonpickle from 1.4.2 to 1.5.0. [dependabot[bot]]

  Bumps [jsonpickle](https://github.com/jsonpickle/jsonpickle) from 1.4.2 to 1.5.0.
  - [Release notes](https://github.com/jsonpickle/jsonpickle/releases)
  - [Changelog](https://github.com/jsonpickle/jsonpickle/blob/master/CHANGES.rst)
  - [Commits](https://github.com/jsonpickle/jsonpickle/compare/v1.4.2...v1.5.0)

* Merge pull request #588 from cve-search/dependabot/pip/pytest-cov-2.11.0. [PT]

  Bump pytest-cov from 2.10.1 to 2.11.0

* Bump pytest-cov from 2.10.1 to 2.11.0. [dependabot[bot]]

  Bumps [pytest-cov](https://github.com/pytest-dev/pytest-cov) from 2.10.1 to 2.11.0.
  - [Release notes](https://github.com/pytest-dev/pytest-cov/releases)
  - [Changelog](https://github.com/pytest-dev/pytest-cov/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest-cov/compare/v2.10.1...v2.11.0)

* Merge pull request #584 from cve-search/dependabot/pip/tqdm-4.56.0. [PT]

  Bump tqdm from 4.55.1 to 4.56.0

* Bump tqdm from 4.55.1 to 4.56.0. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.55.1 to 4.56.0.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.55.1...v4.56.0)

* Merge pull request #583 from cve-search/dependabot/pip/sphinx-3.4.3. [PT]

  Bump sphinx from 3.4.2 to 3.4.3

* Bump sphinx from 3.4.2 to 3.4.3. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.4.2 to 3.4.3.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/3.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.4.2...v3.4.3)

* Merge pull request #582 from P-T-I/cve-search-579. [PT]

  added retry policy to request.session() and removed the sys.exit(1) o…

* Added retry policy to request.session() and removed the sys.exit(1) on error. [Paul Tikken Laptop]

* Merge pull request #580 from cve-search/dependabot/pip/sphinx-rtd-theme-0.5.1. [PT]

  Bump sphinx-rtd-theme from 0.5.0 to 0.5.1

* Bump sphinx-rtd-theme from 0.5.0 to 0.5.1. [dependabot[bot]]

  Bumps [sphinx-rtd-theme](https://github.com/readthedocs/sphinx_rtd_theme) from 0.5.0 to 0.5.1.
  - [Release notes](https://github.com/readthedocs/sphinx_rtd_theme/releases)
  - [Changelog](https://github.com/readthedocs/sphinx_rtd_theme/blob/master/docs/changelog.rst)
  - [Commits](https://github.com/readthedocs/sphinx_rtd_theme/compare/0.5.0...0.5.1)

* Merge pull request #581 from cve-search/dependabot/pip/sphinx-3.4.2. [PT]

  Bump sphinx from 3.4.1 to 3.4.2

* Bump sphinx from 3.4.1 to 3.4.2. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.4.1 to 3.4.2.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/3.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.4.1...v3.4.2)

* Merge pull request #578 from cve-search/dependabot/pip/tqdm-4.55.1. [PT]

  Bump tqdm from 4.55.0 to 4.55.1

* Bump tqdm from 4.55.0 to 4.55.1. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.55.0 to 4.55.1.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.55.0...v4.55.1)

* Merge pull request #577 from cve-search/dependabot/pip/gevent-20.12.1. [PT]

  Bump gevent from 20.12.0 to 20.12.1

* Bump gevent from 20.12.0 to 20.12.1. [dependabot[bot]]

  Bumps [gevent](https://github.com/gevent/gevent) from 20.12.0 to 20.12.1.
  - [Release notes](https://github.com/gevent/gevent/releases)
  - [Changelog](https://github.com/gevent/gevent/blob/master/docs/changelog_pre.rst)
  - [Commits](https://github.com/gevent/gevent/compare/20.12.0...20.12.1)

* Merge pull request #576 from cve-search/dependabot/pip/tqdm-4.55.0. [PT]

  Bump tqdm from 4.54.1 to 4.55.0

* Bump tqdm from 4.54.1 to 4.55.0. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.54.1 to 4.55.0.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.54.1...v4.55.0)

* Merge pull request #575 from cve-search/dependabot/pip/sphinx-3.4.1. [PT]

  Bump sphinx from 3.4.0 to 3.4.1

* Bump sphinx from 3.4.0 to 3.4.1. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.4.0 to 3.4.1.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/3.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.4.0...v3.4.1)

* Update .schema_version. [PT]

  Update schema for new capec version

* Merge pull request #574 from P-T-I/new_capec_version. [PT]

  fix #572: parsing new capec version

* Fix #572: parsing new capec version. [Paul Tikken Laptop]

* Merge pull request #573 from cve-search/dependabot/pip/gevent-20.12.0. [PT]

  Bump gevent from 20.9.0 to 20.12.0

* Bump gevent from 20.9.0 to 20.12.0. [dependabot[bot]]

  Bumps [gevent](https://github.com/gevent/gevent) from 20.9.0 to 20.12.0.
  - [Release notes](https://github.com/gevent/gevent/releases)
  - [Changelog](https://github.com/gevent/gevent/blob/master/docs/changelog_pre.rst)
  - [Commits](https://github.com/gevent/gevent/compare/20.9.0...20.12.0)

* Merge pull request #570 from P-T-I/schema_checker. [PT]

  fix #564; database schema version checker added

* Fix #564; database schema version checker added. [Paul Tikken Laptop]

* Merge pull request #569 from P-T-I/cvss_impact_exploit. [PT]

  added exploit and impact scores to api endpoints; cleanup code and re…

* Added exploit and impact scores to api endpoints; cleanup code and removal of unused functions. [Paul Tikken Laptop]

* Merge pull request #565 from AZobec/cvssV3. [PT]

  add impactScore and exploitabilityScore for CVSS v3.1

* Rebase. [AZobec]

* Add impactScore and exploitabilityScore for CVSS v3.1. [AZobec]

* Merge pull request #568 from cve-search/dependabot/pip/sphinx-3.4.0. [PT]

  Bump sphinx from 3.3.1 to 3.4.0

* Bump sphinx from 3.3.1 to 3.4.0. [dependabot[bot]]

  Bumps [sphinx](https://github.com/sphinx-doc/sphinx) from 3.3.1 to 3.4.0.
  - [Release notes](https://github.com/sphinx-doc/sphinx/releases)
  - [Changelog](https://github.com/sphinx-doc/sphinx/blob/3.x/CHANGES)
  - [Commits](https://github.com/sphinx-doc/sphinx/compare/v3.3.1...v3.4.0)

* Merge pull request #567 from cve-search/dependabot/pip/flask-socketio-5.0.1. [PT]

  Bump flask-socketio from 5.0.0 to 5.0.1

* Bump flask-socketio from 5.0.0 to 5.0.1. [dependabot[bot]]

  Bumps [flask-socketio](https://github.com/miguelgrinberg/Flask-SocketIO) from 5.0.0 to 5.0.1.
  - [Release notes](https://github.com/miguelgrinberg/Flask-SocketIO/releases)
  - [Changelog](https://github.com/miguelgrinberg/Flask-SocketIO/blob/master/CHANGES.md)
  - [Commits](https://github.com/miguelgrinberg/Flask-SocketIO/compare/v5.0.0...v5.0.1)

* Merge pull request #566 from cve-search/dependabot/pip/codecov-2.1.11. [PT]

  Bump codecov from 2.1.10 to 2.1.11

* Bump codecov from 2.1.10 to 2.1.11. [dependabot[bot]]

  Bumps [codecov](https://github.com/codecov/codecov-python) from 2.1.10 to 2.1.11.
  - [Release notes](https://github.com/codecov/codecov-python/releases)
  - [Changelog](https://github.com/codecov/codecov-python/blob/master/CHANGELOG.md)
  - [Commits](https://github.com/codecov/codecov-python/compare/v2.1.10...v2.1.11)

* Merge pull request #563 from cve-search/dependabot/pip/requests-2.25.1. [PT]

  Bump requests from 2.25.0 to 2.25.1

* Bump requests from 2.25.0 to 2.25.1. [dependabot[bot]]

  Bumps [requests](https://github.com/psf/requests) from 2.25.0 to 2.25.1.
  - [Release notes](https://github.com/psf/requests/releases)
  - [Changelog](https://github.com/psf/requests/blob/master/HISTORY.md)
  - [Commits](https://github.com/psf/requests/compare/v2.25.0...v2.25.1)

* Update VERSION. [PT]

* Merge pull request #562 from P-T-I/cve-search-560. [PT]

  Cve search 560

* Added cvss version selector. [Paul Tikken Laptop]

* Added cvss3 filter logic. [Paul Tikken Laptop]

* Added data column for cvss3. [Paul Tikken Laptop]

* Added column for cvss3. [Paul Tikken Laptop]

* Added index for cvss3. [Paul Tikken Laptop]

* Merge pull request #561 from P-T-I/cve-search-559. [PT]

  Cve search 559

* Merge up_master. [Paul Tikken Laptop]

* Merge pull request #522 from AZobec/cvssV3. [PT]

  Add CVSS v3.1 in db and WebUI

* Adding conditions if cvssV3 is None. [AZobec]

* Rebase and adjust web/VERSION. [AZobec]

* Rebase + adjust web/VERSION. [AZobec]

* Modify Version. [AZobec]

* Change version CVSS V3. [AZobec]

* Remove comments. [AZobec]

* Merge remote-tracking branch 'upstream/master' [AZobec]

* CVSSv3 handling - fixing None for absence of V3 score. [AZobec]

* Fix CVSSv3 Handling. [AZobec]

* Add CVSS v3.1 handling. [AZobec]

* Merge pull request #557 from cve-search/dependabot/pip/pytest-6.2.1. [PT]

  Bump pytest from 6.2.0 to 6.2.1

* Bump pytest from 6.2.0 to 6.2.1. [dependabot[bot]]

  Bumps [pytest](https://github.com/pytest-dev/pytest) from 6.2.0 to 6.2.1.
  - [Release notes](https://github.com/pytest-dev/pytest/releases)
  - [Changelog](https://github.com/pytest-dev/pytest/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest/compare/6.2.0...6.2.1)

* Fix #559; added api support for cvssV3 fields. [Paul Tikken Laptop]

* Merge pull request #556 from P-T-I/cve-search-555. [PT]

  fix #555; Double entries in cwe related_weaknesses field

* Fix #555; Double entries in cwe related_weaknesses field. [Paul Tikken Laptop]

* Update query.py. [PT]

* Update ApiRequests.py. [PT]

* Merge pull request #552 from cve-search/dependabot/pip/flask-socketio-5.0.0. [PT]

  Bump flask-socketio from 4.3.2 to 5.0.0

* Bump flask-socketio from 4.3.2 to 5.0.0. [dependabot[bot]]

  Bumps [flask-socketio](https://github.com/miguelgrinberg/Flask-SocketIO) from 4.3.2 to 5.0.0.
  - [Release notes](https://github.com/miguelgrinberg/Flask-SocketIO/releases)
  - [Changelog](https://github.com/miguelgrinberg/Flask-SocketIO/blob/master/CHANGES.md)
  - [Commits](https://github.com/miguelgrinberg/Flask-SocketIO/compare/v4.3.2...v5.0.0)

* Merge pull request #553 from cve-search/dependabot/pip/pytest-6.2.0. [PT]

  Bump pytest from 6.1.2 to 6.2.0

* Bump pytest from 6.1.2 to 6.2.0. [dependabot[bot]]

  Bumps [pytest](https://github.com/pytest-dev/pytest) from 6.1.2 to 6.2.0.
  - [Release notes](https://github.com/pytest-dev/pytest/releases)
  - [Changelog](https://github.com/pytest-dev/pytest/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest/compare/6.1.2...6.2.0)

* Merge pull request #551 from RoccovanAsselt/bugfix-search-without-via4. [PT]

  added via4 check in getSearchResults() function

* Added via4 check. [Rocco van Asselt]

* Testing auto deploy github pages. [Paul Tikken Laptop]

* Testing auto deploy github pages. [Paul Tikken Laptop]

* Testing auto deploy github pages. [Paul Tikken Laptop]

* Merge pull request #550 from P-T-I/cve-search-548. [PT]

  fix #548; new cwe version release

* Fix #548; new cwe version release. [Paul Tikken Laptop]

* Added queues clear to all classes. [Paul Tikken Laptop]

* Merge pull request #547 from RoccovanAsselt/Clearing_queue. [PT]

  clear queues to prevent duplicates

* Use self.queue. [RoccovanAsselt]

* Moved clearing to populate() function. [RoccovanAsselt]

* Clear queues. [RoccovanAsselt]

* Merge pull request #549 from P-T-I/docs_updates. [PT]

  Docs updates

* Minor. [Paul Tikken Laptop]

* Old doc folder cleanup. [Paul Tikken Laptop]

* Doc alteration. [Paul Tikken Laptop]

* Merge pull request #545 from cve-search/dependabot/pip/tqdm-4.54.1. [PT]

  Bump tqdm from 4.54.0 to 4.54.1

* Bump tqdm from 4.54.0 to 4.54.1. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.54.0 to 4.54.1.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.54.0...v4.54.1)

* Delete certificate.crt. [PT]

* Delete certificate.key. [PT]

* Setting up sphinx docs. [Paul Tikken Laptop]

* Rebuild pages. [Paul Tikken Laptop]

* Setting up sphinx docs. [Paul Tikken Laptop]

* Setting up sphinx docs. [Paul Tikken Laptop]

* Setting up sphinx docs. [Paul Tikken Laptop]

* Setting up sphinx docs. [Paul Tikken Laptop]

* Merge pull request #544 from P-T-I/new_docs. [PT]

  New docs; first setup

* Setting up sphinx docs. [Paul Tikken Laptop]

* Merge up_master. [Paul Tikken Laptop]

* Finished migrating unit tests from travis to github actions. [Paul Tikken Laptop]

* Merge pull request #543 from P-T-I/master. [PT]

  testing web test default branch

* Testing web test default branch. [Paul Tikken Laptop]

* Testing web test default branch. [Paul Tikken Laptop]

* Merge pull request #542 from P-T-I/master. [PT]

  testing web test default branch

* Testing web test default branch. [Paul Tikken Laptop]

* Merge pull request #541 from P-T-I/master. [PT]

  Testing PR

* Testing web test default branch. [Paul Tikken Laptop]

* Merge branch 'up_master' [Paul Tikken Laptop]

* Testing web test default branch. [Paul Tikken Laptop]

* Testing web test default branch. [Paul Tikken Laptop]

* Testing web test default branch. [Paul Tikken Laptop]

* Testing web test default branch. [Paul Tikken Laptop]

* Setting up web page tests. [Paul Tikken Laptop]

* Setting up web page tests. [Paul Tikken Laptop]

* Added gh action badge to README.md. [Paul Tikken Laptop]

* Splitting build and test. [Paul Tikken Laptop]

* Testing cache. [Paul Tikken Laptop]

* Testing cache. [Paul Tikken Laptop]

* Testing cache. [Paul Tikken Laptop]

* Testing cache. [Paul Tikken Laptop]

* Testing cache. [Paul Tikken Laptop]

* Testing cache. [Paul Tikken Laptop]

* Testing cache. [Paul Tikken Laptop]

* Uploading pytest reports to gh actions. [Paul Tikken Laptop]

* Uploading pytest reports to gh actions. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Splitting build and test jobs. [Paul Tikken Laptop]

* Merge branch 'master' of https://github.com/cve-search/cve-search into up_master. [Paul Tikken Laptop]

* Merge pull request #540 from cve-search/dependabot/pip/tqdm-4.54.0. [PT]

  Bump tqdm from 4.50.2 to 4.54.0

* Bump tqdm from 4.50.2 to 4.54.0. [dependabot[bot]]

  Bumps [tqdm](https://github.com/tqdm/tqdm) from 4.50.2 to 4.54.0.
  - [Release notes](https://github.com/tqdm/tqdm/releases)
  - [Commits](https://github.com/tqdm/tqdm/compare/v4.50.2...v4.54.0)

* Merge pull request #539 from cve-search/dependabot/pip/pymongo-3.11.2. [PT]

  Bump pymongo from 3.11.0 to 3.11.2

* Bump pymongo from 3.11.0 to 3.11.2. [dependabot[bot]]

  Bumps [pymongo](https://github.com/mongodb/mongo-python-driver) from 3.11.0 to 3.11.2.
  - [Release notes](https://github.com/mongodb/mongo-python-driver/releases)
  - [Changelog](https://github.com/mongodb/mongo-python-driver/blob/3.11.2/doc/changelog.rst)
  - [Commits](https://github.com/mongodb/mongo-python-driver/compare/3.11.0...3.11.2)

* Merge pull request #538 from cve-search/dependabot/pip/jsonpickle-1.4.2. [PT]

  Bump jsonpickle from 1.4.1 to 1.4.2

* Bump jsonpickle from 1.4.1 to 1.4.2. [dependabot[bot]]

  Bumps [jsonpickle](https://github.com/jsonpickle/jsonpickle) from 1.4.1 to 1.4.2.
  - [Release notes](https://github.com/jsonpickle/jsonpickle/releases)
  - [Changelog](https://github.com/jsonpickle/jsonpickle/blob/master/CHANGES.rst)
  - [Commits](https://github.com/jsonpickle/jsonpickle/compare/v1.4.1...v1.4.2)

* Splitting build and test jobs. [Paul Tikken Laptop]

* Merge branch 'up_master' [Paul Tikken Laptop]

* Merge branch 'up_master' [Paul Tikken Laptop]

* Base coverage file. [Paul Tikken Laptop]

* Working on new_docs. [Paul Tikken Laptop]

* Merge branch 'up_master' into new_docs. [Paul Tikken Laptop]

* Merge pull request #537 from cve-search/dependabot/pip/flask-jwt-extended-3.25.0. [PT]

  Bump flask-jwt-extended from 3.24.1 to 3.25.0

* Bump flask-jwt-extended from 3.24.1 to 3.25.0. [dependabot[bot]]

  Bumps [flask-jwt-extended](https://github.com/vimalloc/flask-jwt-extended) from 3.24.1 to 3.25.0.
  - [Release notes](https://github.com/vimalloc/flask-jwt-extended/releases)
  - [Commits](https://github.com/vimalloc/flask-jwt-extended/compare/3.24.1...3.25.0)

* Merge pull request #535 from cve-search/dependabot/pip/ijson-3.1.3. [PT]

  Bump ijson from 3.1.2 to 3.1.3

* Bump ijson from 3.1.2 to 3.1.3. [dependabot[bot]]

  Bumps [ijson](https://github.com/ICRAR/ijson) from 3.1.2 to 3.1.3.
  - [Release notes](https://github.com/ICRAR/ijson/releases)
  - [Changelog](https://github.com/ICRAR/ijson/blob/master/CHANGELOG.md)
  - [Commits](https://github.com/ICRAR/ijson/compare/v3.1.2...v3.1.3)

* Merge pull request #536 from cve-search/dependabot/pip/requests-2.25.0. [PT]

  Bump requests from 2.24.0 to 2.25.0

* Bump requests from 2.24.0 to 2.25.0. [dependabot[bot]]

  Bumps [requests](https://github.com/psf/requests) from 2.24.0 to 2.25.0.
  - [Release notes](https://github.com/psf/requests/releases)
  - [Changelog](https://github.com/psf/requests/blob/master/HISTORY.md)
  - [Commits](https://github.com/psf/requests/compare/v2.24.0...v2.25.0)

* Merge pull request #534 from cve-search/dependabot/pip/pytest-6.1.2. [PT]

  Bump pytest from 6.1.1 to 6.1.2

* Bump pytest from 6.1.1 to 6.1.2. [dependabot[bot]]

  Bumps [pytest](https://github.com/pytest-dev/pytest) from 6.1.1 to 6.1.2.
  - [Release notes](https://github.com/pytest-dev/pytest/releases)
  - [Changelog](https://github.com/pytest-dev/pytest/blob/master/CHANGELOG.rst)
  - [Commits](https://github.com/pytest-dev/pytest/compare/6.1.1...6.1.2)

* Merge pull request #533 from cve-search/dependabot/pip/flask-socketio-4.3.2. [PT]

  Bump flask-socketio from 4.3.1 to 4.3.2

* Bump flask-socketio from 4.3.1 to 4.3.2. [dependabot[bot]]

  Bumps [flask-socketio](https://github.com/miguelgrinberg/Flask-SocketIO) from 4.3.1 to 4.3.2.
  - [Release notes](https://github.com/miguelgrinberg/Flask-SocketIO/releases)
  - [Changelog](https://github.com/miguelgrinberg/Flask-SocketIO/blob/master/CHANGES.md)
  - [Commits](https://github.com/miguelgrinberg/Flask-SocketIO/compare/v4.3.1...v4.3.2)

* Dependabot. [PT]

* Merge branch 'up_master' into new_docs. [Paul Tikken Laptop]

* Cleanup. [Paul Tikken Laptop]

* Disabling travis ci. [Paul Tikken Laptop]

* Merge pull request #532 from P-T-I/master. [PT]

  Added base coverage report

* Merge branch 'master' into new_docs. [Paul Tikken Laptop]

* Base coverage file. [Paul Tikken Laptop]

* Merge master. [Paul Tikken Laptop]

* Merge pull request #531 from P-T-I/code_cov_test. [PT]

  Code cov test

* Code_cov_test. [Paul Tikken Laptop]

* Merge branch 'master' into code_cov_test. [Paul Tikken Laptop]

* Code_cov_test. [Paul Tikken Laptop]

* Code_cov_test. [Paul Tikken Laptop]

* Merge pull request #530 from P-T-I/code_cov_test. [PT]

  moved unit tests to github actions

* Moved unit tests to github actions. [Paul Tikken Laptop]

* Merge pull request #529 from P-T-I/master. [PT]

  Switched unit tests to github actions

* Moved unit tests to github actions. [Paul Tikken Laptop]

* Testing with gh_actions. [Paul Tikken Laptop]

* Testing with gh_actions. [Paul Tikken Laptop]

* Testing with gh_actions. [Paul Tikken Laptop]

* Testing with gh_actions. [Paul Tikken Laptop]

* Merge pull request #2 from P-T-I/GH_action_test. [PT]

  testing with gh_actions

* Testing with gh_actions. [Paul Tikken Laptop]

* Update unit_tests.yml. [PT]

* Update unit_tests.yml. [PT]

* Update unit_tests.yml. [PT]

* Update unit_tests.yml. [PT]

* Merge pull request #1 from P-T-I/gh_action_test. [PT]

  testing with gh_actions

* Testing with gh_actions. [Paul Tikken Laptop]

* Merge branch 'up_master' into new_docs. [Paul Tikken Laptop]

* Merge pull request #528 from P-T-I/cve-search-523. [PT]

  Duplicate id in cpe collection

* Fix #523; Duplicate id in cpe collection. [Paul Tikken Laptop]

* Merge branch 'up_master' [Paul Tikken Laptop]

* Merge branch 'up_master' [Paul Tikken Laptop]

* Bump. [Paul Tikken Laptop]

* Merge pull request #526 from P-T-I/travis_new_test. [PT]

  updated the sleep time for PR

* Updated the sleep time for PR. [Paul Tikken Laptop]

* Delete dependabot.yml. [PT]

* Merge pull request #525 from RoccovanAsselt/set-index-on-populating. [PT]

  new pr: create index on populating cpe and cve

* Rebase. [RoccovanAsselt]

* Merge. [RoccovanAsselt]

* Added functionaly to create index on specific collection and call it on populating cpe and cves. [RoccovanAsselt]

* Added functionaly to create index on specific collection and call it on populating cpe and cves. [RoccovanAsselt]

* Merge pull request #519 from P-T-I/travis_test. [PT]

  gevent support checking

* Setting sleep value higher to allow docker to fully load. [Paul Tikken Laptop]

* Merge branch 'up_master' into travis_test. [Paul Tikken Laptop]

* Added logline. [Paul Tikken Laptop]

* Gevent support checking. [Paul Tikken Laptop]

* Create dependabot.yml. [PT]

* Setting up sphinx docs. [Paul Tikken Laptop]

* Merge branch 'master' into new_docs. [Paul Tikken Laptop]

* Bump. [Paul Tikken Laptop]

* Merge pull request #521 from FafnerKeyZee/patch-1. [PT]

  Starting flask without SSL

* Starting flask without SSL. [Fafner [_KeyZee_]]

  Starting flask without SSL

* Merge pull request #508 from P-T-I/cve-search-399. [Alexandre Dulaunoy]

  Cve search 399

* Fix #513; added two exception handlers; one for the absence of the last_modified header and one for general download failure which will solve issue 513. [Paul Tikken Laptop]

* Minor. [Paul Tikken Laptop]

* Added limit and skip integer checking and exception handling. [Paul Tikken Laptop]

* Fix for search field. [Paul Tikken Laptop]

* Added comment. [Paul Tikken Laptop]

* Removed added additional fields from cve display. [Paul Tikken Laptop]

* Moved vendor table to DataTable with ajax processing. [Paul Tikken Laptop]

* Removed websockets. [Paul Tikken Laptop]

* Added htmlescape function. [Paul Tikken Laptop]

* Fix for not displaying results on api/cvefor. [Paul Tikken Laptop]

* Minor. [Paul Tikken Laptop]

* Query optimalization on cvesForCPE query. [Paul Tikken Laptop]

* Working on new indexes and import fields. [Paul Tikken Laptop]

* Possible fix for travis failing to build. [Paul Tikken Laptop]

* Moved user functions to mongodb.py. [Paul Tikken Laptop]

* Refactor. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Removed allow_disk_use to query_docs queries. [Paul Tikken Laptop]

* Added allow_disk_use to query_docs queries. [Paul Tikken Laptop]

* Disabled loggers. [Paul Tikken Laptop]

* Fix for python path. [Paul Tikken Laptop]

* Fix for python path. [Paul Tikken Laptop]

* Fix for python path. [Paul Tikken Laptop]

* Merge up_master. [Paul Tikken Laptop]

* Bump. [Paul Tikken Laptop]

* Cleanup. [Paul Tikken Laptop]

* Cleanup & black formatting. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Working on websockets. [Paul Tikken Laptop]

* Moved to gevent as webserver. [Paul Tikken Laptop]

* Defined limit and skip as integers. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Moved old files to _old_ folder. [Paul Tikken Laptop]

* Finished porting admin api to new api. [Paul Tikken Laptop]

* Finished porting admin api to new api. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Working on admin api. [Paul Tikken Laptop]

* Working on admin part. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Status adjustments. [Paul Tikken Laptop]

* Working on admin api. [Paul Tikken Laptop]

* Reformatted admin, login with local database fixed; working on white and black list handling. [Paul Tikken Laptop]

* Minor. [Paul Tikken Laptop]

* Password check fix. [Paul Tikken Laptop]

* Added sweetalert2.min.js. [Paul Tikken Laptop]

* Added sweetalert2.min.js. [Paul Tikken Laptop]

* Bump. [Paul Tikken Laptop]

* Merge branch 'up_master' into cve-search-399. [Paul Tikken Laptop]

* Bump. [Paul Tikken Laptop]

* Minimal setting ignoring admin blueprint. [Paul Tikken Laptop]

* Login forms formatting. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Minor. [Paul Tikken Laptop]

* Working on login. [Paul Tikken Laptop]

* Altered hashing mechanism's. [Paul Tikken Laptop]

* Renamed master-page to master-page.html. [Paul Tikken Laptop]

* Added requirements. [Paul Tikken Laptop]

* Removed clipboard. [Paul Tikken Laptop]

* Added socket.io scripts. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Reformatting. [Paul Tikken Laptop]

* Added separate breadcrumbs.html subpage to ease breadcrumbs import into templates. [Paul Tikken Laptop]

* Alterations made to facilitate port to bootstrap 4. [Paul Tikken Laptop]

* Reformatted to bootstrap 4. [Paul Tikken Laptop]

* Working on website restructure. [Paul Tikken Laptop]

* Typo. [Paul Tikken Laptop]

* Added api docs link to default menubar. [Paul Tikken Laptop]

* Req update. [Paul Tikken Laptop]

* Merge branch 'up_master' into cve-search-399. [Paul Tikken Laptop]

* Refactor. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Formatted admin page and index page. [Paul Tikken Laptop]

* Setup logging. [Paul Tikken Laptop]

* Setup datatables and filtering. [Paul Tikken Laptop]

* Setup datatables and filtering. [Paul Tikken Laptop]

* Setup datatables and filtering. [Paul Tikken Laptop]

* Restructured logging. [Paul Tikken Laptop]

* Restructured logging. [Paul Tikken Laptop]

* Restructured logging. [Paul Tikken Laptop]

* Updated requirements.txt. [Paul Tikken Laptop]

* Refactor. [Paul Tikken Laptop]

* Alterations for datatables server side processing. [Paul Tikken Laptop]

* Added formatting and javascript code. [Paul Tikken Laptop]

* Version bump. [Paul Tikken Laptop]

* Rewritten POST query endpoint to make use of the database plugin method instead of a fixed connection to mongodb. [Paul Tikken Laptop]

* Renamed mongo to database to make it more backend agnostic. [Paul Tikken Laptop]

* Updated requirements.txt. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Basic API functionality done. [Paul Tikken Laptop]

* Working on api. [Paul Tikken Laptop]

* Moved to _old_ [Paul Tikken Laptop]

* Working on restructure API. [Paul Tikken Laptop]

* Working on API. [Paul Tikken Laptop]

* Working on converting api into a flask-restx documented api. [Paul Tikken Laptop]

* Updated requirements.txt to latest versions and refactor after changes. [Paul Tikken Laptop]

* Added cve logo to all versions of web gui. [Paul Tikken Laptop]

* Restructure of webgui. [Paul Tikken Laptop]

* New jquery, bootstrap and font-awesome. [Paul Tikken Laptop]

* Black formatting and swithed to central logging. [Paul Tikken Laptop]

* Black formatting and swithed to central logging. [Paul Tikken Laptop]

* Unignored plugin folder in web. [Paul Tikken Laptop]

* Remodelling web interface to facilitate new api. [Paul Tikken Laptop]

* Rebase. [Paul Tikken Laptop]

* Initial setup for a post query endpoint via json body. [Paul Tikken Laptop]

* Moved update scripts to separate log file handler. [Paul Tikken Laptop]

* Working on sphinx docs. [Paul Tikken Laptop]

* Setting up sphinx docs. [Paul Tikken Laptop]

* Setting up sphinx docs. [Paul Tikken Laptop]

* Setting up shinx docs. [Paul Tikken Laptop]

* Setting up shinx docs. [Paul Tikken Laptop]

* Merge pull request #503 from RoccovanAsselt/getCWEstype. [PT]

  bug - "/api/cwe/<int:cwe_id>" always returns null

* Different solution to fix bug. [RoccovanAsselt]

* Bug fix getCWEs function. [RoccovanAsselt]

* Merge pull request #502 from hack3r-0m/master. [PT]

  fix #494

* Update requirements.txt. [hack3r-0m]

  updated PyMongo to 3.11.0 to use `allow_disk_use`

* Fixing #494. [hack3r-0m]

  - added `allow_disk_use` for mongoDB > 4.4
  - changed -1 to pymongo.DESCENDING wherever required

* Merge pull request #1 from cve-search/master. [hack3r-0m]

  making it up to date

* Fixed typo when comparing passwords. [PT]

* Merge pull request #497 from RoccovanAsselt/ConfigBugFix. [Alexandre Dulaunoy]

  Config bug

* Added reloadConfiguration() function to make sure all configs are reloaded. [RoccovanAsselt]

* Merge pull request #495 from P-T-I/cve-search-390. [Alexandre Dulaunoy]

  fixes cve-search-390

* Debugged after failing unit tests. [Paul Tikken Laptop]

* Fixes cve-search-390. [Paul Tikken Laptop]

* Merge pull request #493 from P-T-I/cve-search-492. [Alexandre Dulaunoy]

  Fix #cve-search-492;  api regex searches

* Fix #cve-search-492; CVE mathching not returning the correct amount of results. [Paul Tikken Laptop]

* Merge pull request #491 from P-T-I/unit_tests. [Alexandre Dulaunoy]

  Unit tests

* Merge master. [Paul Tikken Laptop]

* Merge pull request #490 from P-T-I/cleanup. [Alexandre Dulaunoy]

  General Cleanup and black formatting

* Local coverage and test report. [Paul Tikken Laptop]

* Minor. [Paul Tikken Laptop]

* Excluded bot's and fulltext from unit_tests. [Paul Tikken Laptop]

* Reformat and moved cve class from 'last' to CveHandler. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Optimized imports. [Paul Tikken Laptop]

* Black formatting and removed timing attack on password comparison. [Paul Tikken Laptop]

* Deleted unused code. [Paul Tikken Laptop]

* Switched to tqdm instead of custom progressbar. [Paul Tikken Laptop]

* Merge pull request #489 from P-T-I/cve-search-393. [Alexandre Dulaunoy]

  fix for #cve-search-393; added limit for the cve_for api endpoint

* Fix for #cve-search-393; added limit for the cve_for api endpoint. [Paul Tikken Laptop]

* Fix for #cve-search-393; added limit for the cve_for api endpoint. [Paul Tikken Laptop]

* Added unit_tests. [Paul Tikken Laptop]

* Local coverage and test report. [Paul Tikken Laptop]

* Merge branch 'up_master' into unit_tests. [Paul Tikken Laptop]

* Merge pull request #488 from P-T-I/cve-search-487. [Alexandre Dulaunoy]

  Cve search 487

* Adjusted methods for capec and cwe retrieval. [Paul Tikken Laptop]

* Fix #cve-search-487; api endpoint returned the wrong values. Added additional endpoints to request a single capec. [Paul Tikken Laptop]

* Api documentation update. [Paul Tikken Laptop]

* Merge branch 'master' into unit_tests. [Paul Tikken Laptop]

* Merge pull request #486 from P-T-I/readme_update. [Alexandre Dulaunoy]

  update readme

* Update readme. [Paul Tikken Laptop]

* Merge branch 'master' into unit_tests. [Paul Tikken Laptop]

* Merge pull request #485 from P-T-I/travis_test. [Alexandre Dulaunoy]

  possible fix for travis failing on master commit

* Possible fix for travis failing on master commit. [Paul Tikken Laptop]

* Possible fix for travis failing on master commit. [Paul Tikken Laptop]

* Merge pull request #483 from P-T-I/cve-search-462. [Alexandre Dulaunoy]

  Cve search 462

* Set default cvss score to None instead of 5 when no score is present. [Paul Tikken Laptop]

* Syntax errors fixed. [Paul Tikken Laptop]

* Local coverage. [Paul Tikken Laptop]

* Added .coverage. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Minor. [Paul Tikken Laptop]

* Merge pull request #482 from P-T-I/capec_cwe. [Alexandre Dulaunoy]

  Capec cwe

* Added website entries to capec site for newly parsed entries in capec collection. [Paul Tikken Laptop]

* [CAPEC] removed unused code; filtered out DEPRECATED entries added additional parsing for mitre attack and execution flow. [Paul Tikken Laptop]

* [CWE] removed unused code; filtered out DEPRECATED entries and reparsed relationships for categories and weaknesses. [Paul Tikken Laptop]

* Changed sources to latest versions. [Paul Tikken Laptop]

* Merge pull request #451 from P-T-I/import_impr. [Alexandre Dulaunoy]

  Initial import restructure

* Final fix for missing field. [Paul Tikken Laptop]

* Fix for missing last-modified field in cve documents. [Paul Tikken Laptop]

* Fix for missing last-modified field in cve documents. [Paul Tikken Laptop]

* Minor adjustment travis.yml. [Paul Tikken Laptop]

* Merge from master. [Paul Tikken Laptop]

* Merge pull request #478 from P-T-I/unit_tests. [Alexandre Dulaunoy]

  Unit tests

* Added specific parser to BeautifulSoup. [Paul Tikken Laptop]

* Added build arguments to travis file. [Paul Tikken Laptop]

* Final travis file. [Paul Tikken Laptop]

* Working on tests. [Paul Tikken Laptop]

* Working on tests. [Paul Tikken Laptop]

* Working on tests. [Paul Tikken Laptop]

* Working on tests. [Paul Tikken Laptop]

* Added BeautifulSoup to requirements. [Paul Tikken Laptop]

* Working on unit tests. [Paul Tikken Laptop]

* Working on unit tests. [Paul Tikken Laptop]

* Added dict to xml requirement. [Paul Tikken Laptop]

* Fix search.py not returning xml. [Paul Tikken Laptop]

* Testing_travis. [Paul Tikken Laptop]

* Testing_travis. [Paul Tikken Laptop]

* Testing_travis. [Paul Tikken Laptop]

* Testing_travis. [Paul Tikken Laptop]

* Testing_travis. [Paul Tikken Laptop]

* Testing_travis. [Paul Tikken Laptop]

* Testing_travis. [Paul Tikken Laptop]

* Testing with travis. [Paul Tikken Laptop]

* Testing travis file. [Paul Tikken Laptop]

* Testing travis file. [Paul Tikken Laptop]

* Testing travis file. [Paul Tikken Laptop]

* Fixed -p switch travis file. [Paul Tikken Laptop]

* Change to unit_tests. [Paul Tikken Laptop]

* Change to unit_tests. [Paul Tikken Laptop]

* Change to unit_tests. [Paul Tikken Laptop]

* Change in unit_tests. [Paul Tikken Laptop]

* Change in unit_tests. [Paul Tikken Laptop]

* Change in unit_tests. [Paul Tikken Laptop]

* Requirements.txt fix. [Paul Tikken Laptop]

* Altered travis for pytest support. [Paul Tikken Laptop]

* Setup unit testing scripts. [Paul Tikken Laptop]

* Init files added when needed for unit_tests. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Added nltk to requirements.txt as it was not covered. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Config files added for testing. [Paul Tikken Laptop]

* Added pytest requirements. [Paul Tikken Laptop]

* Removed old testing file. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Testing with travis. [Paul Tikken Laptop]

* Merge remote-tracking branch 'origin/master' [Paul Tikken Laptop]

* Create stale.yml. [PT]

* Merge branch 'up_master' into import_impr. [Paul Tikken Laptop]

* Merge pull request #470 from P-T-I/cve-search-469. [Alexandre Dulaunoy]

  cve-search-469; fix for not deplaying results

* Cve-search-469; fix for not deplaying results. [Paul Tikken Laptop]

* Merge branch 'up_master' into import_impr. [Paul Tikken Laptop]

* Merge pull request #468 from P-T-I/regex_options. [Alexandre Dulaunoy]

  fix #464; corrects bad fix from #465

* Fix #464; corrects bad fix from #465. [Paul Tikken Laptop]

* Merging. [Paul Tikken Laptop]

* Merge pull request #465 from P-T-I/regex_fail. [Alexandre Dulaunoy]

  Regex fail

* Alter .gitignore. [Paul Tikken]

* Fixes #464; double options (IGNORE_CASE) declaration for a regex search. [Paul Tikken]

* Altered .gitignore. [Paul Tikken]

* Fixed syntax warnings. [Paul Tikken Laptop]

* Added jsonpickle requirement. [Paul Tikken Laptop]

* Added auto creation of log dir. [Paul Tikken Laptop]

* Troubleshooting build error on feedformatter version. [Paul Tikken Laptop]

* Merge branch 'master' into import_impr. [Paul Tikken Laptop]

* Merge pull request #459 from P-T-I/docker_version. [Alexandre Dulaunoy]

  fix #205; official dockerized version of CVE-Search added

* Fix #205; official dockerized version of CVE-Search added. [Paul Tikken Laptop]

* Merge pull request #460 from P-T-I/cve_search_#395. [Alexandre Dulaunoy]

  fix #395; Fixed warning message Mongoclient create pre-fork

* Fix #395; Fixed warning message Mongoclient create pre-fork. [Paul Tikken Laptop]

* Added variable interval counter for debug logging. [Paul Tikken Laptop]

* Corrected update error. [Paul Tikken Laptop]

* Rebase. [Paul Tikken Laptop]

* Merge pull request #456 from P-T-I/syntax_warnings. [Alexandre Dulaunoy]

  Fixed Tornado's syntax warnings

* Fixed Tornado's syntax warnings. [Paul Tikken Laptop]

* Merge pull request #454 from P-T-I/cve_search-449. [Alexandre Dulaunoy]

  fix #449; Added stricter regex for matching CVE on CPE

* Fix #449; added stricter cpe regex when matching CVEs on CPEs. [Paul Tikken Laptop]

* Refactor. [Paul Tikken Laptop]

* Refactor. [Paul Tikken Laptop]

* Refactor. [Paul Tikken Laptop]

* Merge branch 'master' into cve_search-449. [Paul Tikken Laptop]

* Merge pull request #453 from P-T-I/doc_update. [Alexandre Dulaunoy]

  fix #452; Documentation update

* Fix #452; Documentation update to bring the docs in line with the readme.md in the root. [Paul Tikken Laptop]

* Cleanup. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Missing sys import and black formatting. [Paul Tikken Laptop]

* Moved DatabaseIndexer to separate class in Sources_process.py. [Paul Tikken Laptop]

* Moved DatabaseIndexer to separate class in Sources_process.py. [Paul Tikken Laptop]

* Added additional log entries. [Paul Tikken Laptop]

* Changed logger name. [Paul Tikken Laptop]

* Added description to tqdm progressbar from CPERedisBrowser class. [Paul Tikken Laptop]

* Unified logging with updater and black formatting. [Paul Tikken Laptop]

* Import refactor and minor edit. [Paul Tikken Laptop]

* Set JSON file progress debug logging to every 5000 items. [Paul Tikken Laptop]

* Moved logic to process class. [Paul Tikken Laptop]

* Added CPERedisBrowser class. [Paul Tikken Laptop]

* Added logging and tqdm progressbar. [Paul Tikken Laptop]

* Added logging. [Paul Tikken Laptop]

* Fixed misspelled method (getCVEID instead of getCVEIDs) and black formatting. [Paul Tikken Laptop]

* Added debug counter from processing items from file every 1000 items. [Paul Tikken Laptop]

* Added debug counter from processing items from file. [Paul Tikken Laptop]

* Refactor and unified logging with process classes. [Paul Tikken Laptop]

* Refactor and unified logging with process classes. [Paul Tikken Laptop]

* Modified update doc versus insert doc. [Paul Tikken Laptop]

* Moved process classes to separate file. [Paul Tikken Laptop]

* Refactor. [Paul Tikken Laptop]

* Separate file for source process classes. [Paul Tikken Laptop]

* Separate file for xml Content Handlers. [Paul Tikken Laptop]

* Methods refactor. [Paul Tikken Laptop]

* Added process methods to class instead. [Paul Tikken Laptop]

* Changed process_item method. [Paul Tikken Laptop]

* Added process_item to DownloadHandler class. [Paul Tikken Laptop]

* Added method to retrieve the entire redis list. [Paul Tikken Laptop]

* Added process_item to XMLFileHandler class. [Paul Tikken Laptop]

* Added db (9) for redis queue. [Paul Tikken Laptop]

* Added RedisQueue. [Paul Tikken Laptop]

* Moved download_site method to DownloadHandler.py. [Paul Tikken Laptop]

* Added redis queue as a replacement of multiprocessing queue. [Paul Tikken Laptop]

* Added database action class. [Paul Tikken Laptop]

* Refactor. [Paul Tikken Laptop]

* Added additional logging. [Paul Tikken Laptop]

* Minor changes. [Paul Tikken Laptop]

* Reset insert to original. [Paul Tikken Laptop]

* Added different handlers. [Paul Tikken Laptop]

* Added different handlers. [Paul Tikken Laptop]

* Added different handlers. [Paul Tikken Laptop]

* Minor. [Paul Tikken Laptop]

* Minor. [Paul Tikken Laptop]

* Set debug print to every 10 cycles. [Paul Tikken Laptop]

* Added venv and .idea folders to ignore. [Paul Tikken Laptop]

* Set exit code on errors to 1. [Paul Tikken Laptop]

* Added VIADownloads class for update optimalization. [Paul Tikken Laptop]

* Moved updates of info collection to DownloadHandler. [Paul Tikken Laptop]

* Added requirements ijson and tqdm. [Paul Tikken Laptop]

* Added logging and file extension specific classes. [Paul Tikken Laptop]

* Added tqdm and ijson requirements. [Paul Tikken Laptop]

* Added queues and multiprocessing. [Paul Tikken Laptop]

* Added further multiprocessing. [Paul Tikken Laptop]

* Added speed improvements for initial import. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Black formatting. [Paul Tikken Laptop]

* Speed improvements for initial import of data. [Paul Tikken Laptop]

* Merge pull request #450 from P-T-I/web_impr. [Alexandre Dulaunoy]

  minor admin page gui adjustments

* Minor admin page gui adjustments. [Paul Tikken Laptop]

* Merge pull request #448 from P-T-I/query_opt. [Alexandre Dulaunoy]

  small http query optimalization and black formatting

* Small http query optimalization and black formatting. [Paul Tikken Laptop]

* Merge pull request #436 from noraj/patch-2. [Alexandre Dulaunoy]

  add docker ref

* Update README.md. [Alexandre Dulaunoy]

  Make it more markdown friendly.

* Add docker ref. [Alexandre ZANNI]

* Merge pull request #442 from P-T-I/fix_cpe_other. [Alexandre Dulaunoy]

  fix #441

* Fix #441. [Paul Tikken Laptop]

* Merge pull request #444 from P-T-I/capec. [Alexandre Dulaunoy]

  fix #443 and #402 and #414

* Fix #443. [Paul Tikken Laptop]

* Merge pull request #445 from P-T-I/version_bumps. [Alexandre Dulaunoy]

  version bump of cwe and capec

* Version bump of cwe. [Paul Tikken Laptop]

* Merge pull request #438 from AndreC10002/patch-2. [Alexandre Dulaunoy]

  Redis password parameter

* Redis password parameter. [AndreC10002]

  Redis password parameter

* Merge pull request #429 from tydeu/master. [Alexandre Dulaunoy]

  Drop the `cves` (not the `cve`) collection when repopulating

* Drop  the `cves` (not the `cve`) collection. [Mac Malone]

* Merge branch 'master' of github.com:cve-search/cve-search. [Alexandre Dulaunoy]

* Merge pull request #423 from eaydin/master. [Alexandre Dulaunoy]

  Resolve issue #375

* Resolve issue #375. [eaydin]

* Update README.md. [Pidgey]

* Merge pull request #415 from guiguitodelperuu/fix-capec-v3.2. [Alexandre Dulaunoy]

  Add support for the latest CAPEC XML file version (3.2).

* Add support for the lastest CAPEC XML file version (3.2). Issue #414. [Guillaume Petit]

* Merge pull request #412 from Schuilnaam/master. [Alexandre Dulaunoy]

  notification bug fix

* Revert "Update .travis.yml" [rocco]

  This reverts commit ea3059c7344f76748d42ccd1747b085d736cdfcf.

* Update .travis.yml. [Rocc00]

  python 3.3 is not available

* Notification bug fix. [rocco]

* Merge pull request #409 from jgilman99/jgilman99-patch-1. [Alexandre Dulaunoy]

  Typo - `access` spelled `acccess`

* Typo - `access` spelled `acccess` [John]

  Starting cve
  Traceback (most recent call last):
    File "/cve-search/sbin/db_mgmt_json.py", line 202, in <module>
      db.updateCVE(item)
    File "/cve-search/sbin/../lib/DatabaseLayer.py", line 72, in updateCVE
      "vulnerable_product": cve["vulnerable_product"], "access": cve['acccess'],

* Merge pull request #401 from Agh42/feature/improve-bulk-updates. [Alexandre Dulaunoy]

  Speed up bulk update (i.e. CPE update) operations.

* Speed up bulk update operations. [Agh42]

* Merge pull request #391 from kairis/master. [Alexandre Dulaunoy]

  CPE and CVE fixes

* Drop CPE and CVE databases if force populating. [Sami Kairajarvi]

  This is done in db_updater, but if someone calls either
  CPE or CVE updaters directly with "-pa", it will duplicate
  the data

* Change order of updating CVE and CPE. [Sami Kairajarvi]

  CPE needs to be updated first, as CVE uses CPE data

* Add fields to CVE only if they don't exist already. [Sami Kairajarvi]

* Fix CPE matching for vulnerable children. [Sami Kairajarvi]

* Add warning to product search. [Sami Kairajarvi]

* Remove non_vulnerable_configuration. [Sami Kairajarvi]

* Add all vulnerable products to vulnerable_products, not only applications. [Sami Kairajarvi]

* Merge pull request #386 from kairis/master. [Alexandre Dulaunoy]

  Append all items of CVE description field into summary

* Append all items of CVE description field into summary. [Sami Kairajarvi]

* Merge pull request #380 from kairis/master. [Alexandre Dulaunoy]

  Update CPE to use JSON feed

* Add applications to vulnerable_application. [Sami Kairajarvi]

* Add generate_title function. [Sami Kairajarvi]

  Generates a title based on CPE string that is human
  readable

* Update CPE to use JSON feed. [Sami Kairajärvi]

* Merge branch 'janidetiger-master' [Alexandre Dulaunoy]

* Merge branch 'master' of https://github.com/janidetiger/cve-search into janidetiger-master. [Alexandre Dulaunoy]

* Small update. [Ján Doboš]

* Config.py optimalization. [Ján Doboš]

* Config.py optimalization. [Ján Doboš]

* - rework of getMongoConnection() function to correctly catch exception due to changes in pymongo 2.9 and later. [Ján Doboš]

  - update of getMaxLogSize(): default values should be in MB, .lower() replaced by .upper() as b,kb can be confusing when referring to Bytes

  - getCVEStartYear() cleaned

* Merge branch 'janidetiger-master' [Alexandre Dulaunoy]

* Update table.html. [Ján Doboš]

* Update pager.html. [Ján Doboš]

* Update search.html. [Ján Doboš]

* Update pager.js. [Ján Doboš]

* Update minimal.py. [Ján Doboš]

* Update index.py. [Ján Doboš]

* Update db_mgmt_cpe_other_dictionary.py. [Ján Doboš]

* Update Query.py. [Ján Doboš]

* Update DatabaseLayer.py. [Ján Doboš]

* Update CVEs.py. [Ján Doboš]

* Update index.py. [Ján Doboš]

* Update api.py. [Ján Doboš]

* Update table.html. [Ján Doboš]

  - maintain original functionality because of recent changes of return values of getCVEs function
  - we need to access the 'cves' key of the returned dictionary

* Update pager.html. [Ján Doboš]

  complete rework of pagination
  - now correctly calculates the total number of pages and creates correct pagination elements
    - for pages with index close to beginning hides later pages
    - for pages with index in the middle hides some pages in front and some in end
    - for pages with index close to end hides pages in the beginning

* Update filters.html. [Ján Doboš]

  - addition of action="/r/0" tag
  - if filter is set manually, then it changes the resulting data, so we want to display the first page (offset /r/0)

* Update index.html. [Ján Doboš]

  - function setSettings() renamed to SetFilters()
  - if CVE filtering is enabled and sent via POST, setFilters() is run on document.ready and sets values of the filtering elements
    - python variable filters now stores the current filter settings

* Update index-minimal.html. [Ján Doboš]

  - unification of setFilters() javascript function with index.html
  - if CVE filtering has been enabled and sent by POST, setFilters() is called on document.ready and set the current filter values on filtering elements

* Update pager.js. [Ján Doboš]

  - simplification of functions used for pagination
  - function paginator_jump(n) now jumps to the required offset of results and is called by clicking on pagination elements

* Update minimal.py. [Ján Doboš]

  function getFilterSettingsFromPost has been polished

* Update index.py. [Ján Doboš]

  maintain original functionality because of recent changes of return values of getCVEs function

* Update api.py. [Ján Doboš]

  maintain original functionality because of recent changes of return values of getCVEs function

* Update db_mgmt_cpe_other_dictionary.py. [Ján Doboš]

  maintain same functionality because of changes of return values inside the getCVEs function (now return a dictionary)

* Update Query.py. [Ján Doboš]

  - maintain same functionality because of changes of return values of getCVEs function

* Update DatabaseLayer.py. [Ján Doboš]

  - getCVEs
    - update of return values in order to support pagination
    - now returns a dictionary containing both data 'cves' and total number of results  'total' for pagination purposes)
  - getCVEsNewerThan, via4Linked
    - maintain same functionality by selecting the 'cves' result from the dictionary because of update of getCVEs
    - removal of sanitization, because it is already called inside the getCVE function

* Update CVEs.py. [Ján Doboš]

  maintain functionality because of changes of values returned by getCVEs function

* Update search.py. [Ján Doboš]

  maintain same functionality because of changes values returned by getCVEs function

* Merge pull request #374 from FafnerKeyZee/master. [Alexandre Dulaunoy]

  Adding some filters on result page

* Update filters.html. [Fafner [_KeyZee_]]

* Update table.html. [Fafner [_KeyZee_]]

* Update filters.html. [Fafner [_KeyZee_]]

* Update filters.html. [Fafner [_KeyZee_]]

* Update table.html. [Fafner [_KeyZee_]]

* Create filters2.html. [Fafner [_KeyZee_]]

* Update search.html. [Fafner [_KeyZee_]]

* Merge pull request #359 from joanrodriguezr/patch-6. [Alexandre Dulaunoy]

  Keep freetext search value in the top textarea after executing the search.

* Keep free text search text value. [Joan Rodriguez Rodriguez]

  Update this subpage with the recently executed search

* Keep free text search in the top textArea. [Joan Rodriguez Rodriguez]

  Send parameter to the template we want to render with the search text we have executed

* Merge pull request #343 from joanrodriguezr/patch-1. [Alexandre Dulaunoy]

  Fix system crash when empty search

* Fix system crash when empty search. [Joan Rodriguez Rodriguez]

  Fixes #335 issue. It performs an empty search without crashing system. (server side)

* Update scripts.js. [Joan Rodriguez Rodriguez]

  Fixes #335 issue. It performs an empty search without crashing system.

* Merge pull request #344 from joanrodriguezr/patch-2. [Pidgey]

  Fix logout

* Fix logout. [Joan Rodriguez Rodriguez]

  It fixes issue #338. Just change the Method from POST to GET to get it running.

* Missing update for #339. [Pidgey]

* Merge pull request #349 from joanrodriguezr/patch-3. [Pidgey]

  Fix default user agent style in Chrome

* Fix default user agent style in Chrome. [Joan Rodriguez Rodriguez]

  It fixes look&feel in chrome #339. Overriding the user agent stylesheet for "nav navbar-nav"

* Merge pull request #345 from noraj/patch-1. [Alexandre Dulaunoy]

  readme: add missing dep and sort them alphabetically

* Readme: add missing dep and sort them alphabetically. [Alexandre ZANNI]

* Merge pull request #341 from iammyr/pyscan. [Alexandre Dulaunoy]

  new feature:  scan of pip requirements file for CVEs

* Merge branch 'master' into pyscan. [iammyr]

* Merge pull request #333 from siisar/patch-1. [Alexandre Dulaunoy]

  Setting redis password

* Setting redis password. [siisar]

  Optionally, with this change we are able to connect to a Redis server that is protected with a password.
  This password is provided in the configuration.ini, in the Redis section, with the keyword "Password".
  By default, the password is None, as currently happens

* Merge pull request #325 from noraj/patch-1. [Alexandre Dulaunoy]

  readme: whoosh appears two times

* Whoosh appears two times. [Alexandre ZANNI]

* Merge pull request #326 from noraj/patch-2. [Alexandre Dulaunoy]

  readme: add missing deps (from requests.txt)

* Readme: add missing deps (from requests.txt) [Alexandre ZANNI]

* Merge pull request #327 from Grenzdebiel/html-qoute. [Alexandre Dulaunoy]

  Update dump_last.py

* Update dump_last.py. [Rene]

  Add html.escape for summary in html output.

* Merge pull request #320 from itsbriany/multiple_product_search. [Alexandre Dulaunoy]

  Added support to search for multiple products in a single query

* Added support to search for multiple products in a single query. [Brian Yip]

* Merge pull request #322 from SergeOlivierP/cwe-completeness-fix-related. [Alexandre Dulaunoy]

  Cwe completeness: added related weaknesses and categories

* Removed forgetten debugging options. [serge]

* Added support for cases where multiple views use same related weaknesses hierarchy. [serge]

* Removed debugging commented code. [serge]

* Added support for categories. [serge]

* Added ability to force update, useful for debugging purpose. [serge]

* Switched parsing to use version 2.12 of cwe xml. [serge]

* Adding related weaknesses tree structure. [serge]

* Set theme jekyll-theme-minimal. [Alexandre Dulaunoy]

* Merge pull request #311 from StCyr/stcyr-Issue308. [Alexandre Dulaunoy]

  Issue 308: Updated documentation how to fulltext index all the CVEs.

* Issue-308: Improved markdown documentation formating. [Cyrille Bollu]

* Issue 308: Added reference to the /doc folder in the README.md file. [Cyrille Bollu]

* Issue 308: Updated how to fulltext index all the CVEs. [Cyrille Bollu]

  Cyrille

* Merge pull request #301 from CriimBow/patch-1. [Alexandre Dulaunoy]

  Fix error when researching CVE with no CVSS

* Fix error when researching CVE with no CVSS. [Guillaume G]

  Example : ./search.py -c cve-2018-8373
  Format fixed: CSV, HTML, XML

* Merge pull request #306 from CriimBow/patch-1. [Alexandre Dulaunoy]

  Update README to import local VIA4CVE

* Update README to import local VIA4CVE. [Guillaume G]

  Import your own VIA4CVE

* Merge pull request #312 from SteveClement/master. [Alexandre Dulaunoy]

  chg: [doc] Added initial import indication

* Merge pull request #314 from Agh42/master. [Alexandre Dulaunoy]

  Added support for field "vulnerable_product"

* Added support for field vulnerable_product. [Agh42]

  Parser now ingests the field "vulerable_product" from the NVD XML-feed.
  New option "--vulnerable-product-only" uses this field:

  With this option, "-p" will only return vulnerabilities directly
  assigned to the product.

  I.e. it will not consider "windows_7" if it is only mentioned as
  affected OS in a "foxit_reader" vulnerability.

* Merge branch 'master' of https://github.com/CVE-Search/CVE-Search. [PidgeyL]

* Merge pull request #298 from paralax/patch-1. [Alexandre Dulaunoy]

  prettier markdown formatting, no content changes

* Prettier markdown formatting, no content changes. [jose nazario]

* Merge pull request #297 from Anderson-Liu/patch-1. [Alexandre Dulaunoy]

  Update sources.ini.sample

* Update sources.ini.sample. [Anderson]

  Upgrade source to new version.

* License Change to AGPL - Discussed in issue #281. [PidgeyL]

* Merge pull request #289 from Alexandre-Bartel/upto-search-option. [Alexandre Dulaunoy]

  New parameter for 'lax' search

* Added parameter for 'lax' search. [Alexandre Bartel]

* Merge pull request #286 from jbmaillet/fix_nvd_feeds. [Pidgey]

  Update NVD feeds

* Update NVD feeds. [Jean-Baptiste Maillet]

* Merge pull request #284 from Patristo/master. [Alexandre Dulaunoy]

  Fix #283 - db_updater when running a virtualenv executable.

* Fix #283 - db_updater when running a virtualenv executable. [Nathaniel Jensen]

* Merge pull request #257 from chervaliery/master. [Alexandre Dulaunoy]

  Convert wrong encoding of CPE2.3

* Convert wrong encoding of CPE2.3. [chervaliery]

  Add the unquote function to convert the url encoded to escaped character

* Use SSL in all sources. [PidgeyL]

* Add 'ignore certificates' option. [PidgeyL]

* Update CWE version. [PidgeyL]

* Merge pull request #255 from guntbert/master. [Pidgey]

  Improve grammar in the "rationale" paragraph.

* Improve grammar in the "rationale" paragraph. [Guntbert Reiter]

  The last sentence seems to have been built from two sentences...

* Bugfix #247. [PidgeyL]

* Pyscan: dependency from requirements-parser in order to scan pip requirements file. [iammyr]

  #major

* Pyscan: added scan of pip requirements file for CVEs as a new feature. [iammyr]

  #major

* Remove vendor statements, as they are in VIA4. [PidgeyL]

* Bugfix for bson date conversion. [PidgeyL]

* Fix typo in example (-f is full json output) [Alexandre Dulaunoy]

* Fix example as vulnerable_configuration is now cpe version 2.3 (not more 2.2) [Alexandre Dulaunoy]

* Ensure consistent JSON output with previous version of the API for datetime element. [Alexandre Dulaunoy]

  The datetime bson output has a different format and use $date key when dealing
  with datetime value. The output is just kept consistent with the previous version of the API.

* Bug fixed for empty cvss values. [Alexandre Dulaunoy]

* As MongoClient is not safe regarding fork. Connect is set to False by default. [Alexandre Dulaunoy]

* Merge remote-tracking branch 'origin/master' [Alexandre Dulaunoy]

* Merge pull request #237 from IrootGeek/master. [Alexandre Dulaunoy]

  Add ranking to every possible output

* Add new function search text in all summary. [IrootGeek]

* Add ranking text. [IrootGeek]

* Merge remote-tracking branch 'pj/master' [Alexandre Dulaunoy]

* Bugfix comment in #226. [PidgeyL]

* Bugfix #226. [Pieter-Jan Moreels]

* Remove unused script. [Pieter-Jan Moreels]

* Resolve #219. [Pieter-Jan Moreels]

* Implement request #197. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Bugfix #131. [Pidgey]

* Add requests (#130) and sort alphabetically. [Pidgey]

* Documentation update. [PidgeyL]

* Bugfix filter. [PidgeyL]

* Bugfixes + code clean-up. [PidgeyL]

* Bugfix + code clean-up. [PidgeyL]

* Bugfix + code clean-up. [PidgeyL]

* Status codes in documentation. [PidgeyL]

* Fix status codes in web/api. [PidgeyL]

* Add session authentication. [PidgeyL]

* Bugfix #131. [PidgeyL]

* Update readme 'copyright' [PidgeyL]

* Merge branch 'api_reworking' of https://github.com/pidgeyl/cve-search into api_reworking. [PidgeyL]

* Merge branch 'api_reworking' of https://github.com/pidgeyl/cve-search into api_reworking. [PidgeyL]

* Sepparate auth to reduce code. [PidgeyL]

* API Documentation update. [PidgeyL]

* Add query and link to api. [PidgeyL]

* Forgot to add the js. [PidgeyL]

* Token in admin page. [PidgeyL]

* Singleton objects. [PidgeyL]

* Add jsonp support. [PidgeyL]

* Add documentation, advancedAPI & fix info on admin page. [PidgeyL]

* Bugfix via4. [PidgeyL]

* Bugfix + rename cve info collection to cves. [PidgeyL]

* Fix dbStats on admin page. [PidgeyL]

* Fix dbstats. [PidgeyL]

* Initial api reworking. [PidgeyL]

* Add query and link to api. [PidgeyL]

* Sepparate auth to reduce code. [PidgeyL]

* API Documentation update. [PidgeyL]

* Forgot to add the js. [PidgeyL]

* Token in admin page. [PidgeyL]

* Singleton objects. [PidgeyL]

* Add jsonp support. [PidgeyL]

* Add documentation, advancedAPI & fix info on admin page. [PidgeyL]

* Bugfix via4. [PidgeyL]

* Bugfix + rename cve info collection to cves. [PidgeyL]

* Fix dbStats on admin page. [PidgeyL]

* Fix dbstats. [PidgeyL]

* Initial api reworking. [PidgeyL]

* 'self' bugfix. [PidgeyL]

* Merge pull request #230 from igama/master. [Alexandre Dulaunoy]

  Ensure that redis-cache-cpe runs when selected

* Ensure that redis-cache-cpe runs when selected. [igama]

* Merge pull request #217 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes

* Merge pull request #137 from PidgeyL/master. [Alexandre Dulaunoy]

  bugfix for issue described in #216

* Bugfix. [PidgeyL]

* Merge remote-tracking branch 'upstream2/master' [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Bugfix plugin settings for dictionaries. [PidgeyL]

* Merge pull request #212 from jbmaillet/bugfix_web_login_broken. [Pidgey]

* Bugfix: web server login broken. [Jean-Baptiste Maillet]

* VIA4CVE reference added. [Alexandre Dulaunoy]

* Merge pull request #211 from adulau/master. [Alexandre Dulaunoy]

  via4cvs and many other fixes

* Msupdater removed as it's now part of VIA4CVE. [Alexandre Dulaunoy]

* Indent fixed. [Alexandre Dulaunoy]

* Use of bson utils instead of jsonify. [Alexandre Dulaunoy]

* Fix #133. [Alexandre Dulaunoy]

* Fix broken merged. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:PidgeyL/cve-search. [Alexandre Dulaunoy]

  Conflicts:
  	lib/Config.py

* Forgot to load plug-ins. [PidgeyL]

* Add VIA4 source. [PidgeyL]

* Bugfix. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* VIA4CVE default feed added. [Alexandre Dulaunoy]

* Merge pull request #135 from PidgeyL/master. [Alexandre Dulaunoy]

  Replace vFeed with VIA4, and modify the API and web server classes for inheritance

* Bugfixes. [PidgeyL]

* Fix irc & xmpp bot. [Pieter-Jan Moreels]

* API modularization (step 1) [PidgeyL]

* Via4 searchability and linking. [PidgeyL]

* Visualize via4 data. [PidgeyL]

* Initial commit via4. [PidgeyL]

* Merge pull request #209 from rmarsollier/refactoring. [Alexandre Dulaunoy]

  refactoring of displaying functions and usage of them in cveid search mode (-c)

* Refactoring of displaying functions and usage of them in more mode (-c) [robin.marsollier]

* Merge pull request #204 from pombredanne/patch-2. [Alexandre Dulaunoy]

  Create proper __init__.py to make lib a module

* Create proper __init__.py to make lib a module. [Philippe Ombredanne]

  lib is not a package but is used as such with absolute imports. The proper way is to make this a bona fide package with an __init__.py

* Merge pull request #208 from adulau/master. [Alexandre Dulaunoy]

  New reference lookup added + bug fixes

* References database added in the README. [Alexandre Dulaunoy]

* How to add cross-references. [Alexandre Dulaunoy]

* Add: more references added. [Alexandre Dulaunoy]

* Clarification about the initial CPE import that might take some time. [Alexandre Dulaunoy]

* Merge remote-tracking branch 'pidgeyl/master' [Alexandre Dulaunoy]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Bugfix #129. [Pieter-Jan Moreels]

* Try to remove vFeed (step 1) [PidgeyL]

* Bugfix. [PidgeyL]

* Bugfix database population. [Pieter-Jan Moreels]

* VFeed replacement. [Pieter-Jan Moreels]

* Bugfix. [PidgeyL]

* Merge pull request #206 from adulau/master. [Alexandre Dulaunoy]

  Many bug fixes and clean-up (including the removal of vfeed)

* Merge pull request #134 from PidgeyL/master. [Alexandre Dulaunoy]

  Several bugfixes and minor changes

* Remove vFeed as a source since it's not automatable anymore. [PidgeyL]

* Bugfix for #128. [PidgeyL]

* Make it possible to hide white&blacklist from unauthenticated users. [PidgeyL]

* Temporarily disable vfeed while looking for alternative sources for data. [PidgeyL]

* Add get option on /r/<int:r> [PidgeyL]

* Change the way sources are accessed & move sources & make it more scalable. [PidgeyL]

* Merge branch 'master' of github.com:cve-search/cve-search. [Alexandre Dulaunoy]

* Merge pull request #202 from pombredanne/patch-1. [Alexandre Dulaunoy]

  Simplify places to fetch sources in install doc

* Simplify places to fetch sources in install doc. [Philippe Ombredanne]

  * List only cve-search as the place to fetch sources
  * Other forks do not seem entirely up to date

* Merge pull request #132 from PidgeyL/master. [Alexandre Dulaunoy]

  pam style authentication manager + bugfixes

* Merge remote-tracking branch 'upstream+/master' [Pieter-Jan Moreels]

* Merge pull request #199 from sec9/fix-utf8-encoding-issue. [Alexandre Dulaunoy]

  Fix UTF-8 encoding issue when parsing CWE and ExploitDB Files

* Fix UTF-8 encoding issue when parsing CWE and ExploitDB Files. [Sebastien AUCOUTURIER]

* Clarification regarding the proprietary vfeed database. [Alexandre Dulaunoy]

* Merge pull request #196 from igama/master. [Alexandre Dulaunoy]

  Update NIST Vendor Statements processing

* Update data format on parsing NIST Vendor Statements. [Marco Silva]

* Update NIST Vendor Statements url. [Marco Silva]

* Cve_refs added - first version to lookup NIST ref database. [Alexandre Dulaunoy]

  cve_refs.py queries the Redis database where the NIST ref are.

  You can query a CVE id and it will return the known references by NIST.
  If you use the option "-u", the URL expansion is done. The expansion
  table is not complete and need to be extended. This codes might move
  in the core cve-search library soon.

  python3 cve_refs.py -u -c CVE-2016-3100

  SUSE:openSUSE-SU-2016:1723
  https://bugs.kde.org/show_bug.cgi?id=363140
  https://www.kde.org/info/security/advisory-20160621-1.txt
  https://quickgit.kde.org/?p=kinit.git&a=commitdiff&h=dece8fd89979cd1a86c03bcaceef6e9221e8d8cd
  https://quickgit.kde.org/?p=kinit.git&a=commitdiff&h=72f3702dbe6cf15c06dc13da2c99c864e9022a58
  http://www.kde.com/announcements/kde-frameworks-5.23.0.php
  https://bugs.kde.org/show_bug.cgi?id=358593

  python3 cve_refs.py -c CVE-2016-3100
  CONFIRM:https://www.kde.org/info/security/advisory-20160621-1.txt
  CONFIRM:https://bugs.kde.org/show_bug.cgi?id=358593
  CONFIRM:https://bugs.kde.org/show_bug.cgi?id=363140
  CONFIRM:https://quickgit.kde.org/?p=kinit.git&a=commitdiff&h=72f3702dbe6cf15c06dc13da2c99c864e9022a58
  SUSE:openSUSE-SU-2016:1723
  CONFIRM:https://quickgit.kde.org/?p=kinit.git&a=commitdiff&h=dece8fd89979cd1a86c03bcaceef6e9221e8d8cd
  CONFIRM:http://www.kde.com/announcements/kde-frameworks-5.23.0.php

* Fix #198. [Alexandre Dulaunoy]

* Merge pull request #194 from igama/master. [Pidgey]

  Variable name should be errors in /r/<int:r>

* Variable name should be errors in /r/<int:r> [Marco Silva]

* Merge branch 'master' of github.com:cve-search/cve-search. [Alexandre Dulaunoy]

* Minimal API documentation added. [Alexandre Dulaunoy]

* Send pending bugfix. [Pieter-Jan Moreels]

* Incomplete fix for #188. [PidgeyL]

* Bugfix for #188. [PidgeyL]

* Add readme for authentication modules. [PidgeyL]

* Bugfix for Issue #184. [PidgeyL]

* Fix typo. [PidgeyL]

* Change shebang from python3.3 to python3 (compatibility) [PidgeyL]

* Merge remote-tracking branch 'upstream+/master' [PidgeyL]

* PluginManager: handling of configuration file. [Jean-Baptiste Maillet]

  Handle spaces as well as tabs, use portable splitlines().

* Merge pull request #186 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes

* Merge pull request #183 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #131 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfix

* Merge pull request #130 from PidgeyL/master. [Alexandre Dulaunoy]

  bugfixes

* Authentication manager. [PidgeyL]

* Move password hashing to database layer. [PidgeyL]

* Bugfix multiplier & bugfix kb. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #177 from jbmaillet/pip_requirements_web_add_missing. [Alexandre Dulaunoy]

  Add missing Python modules required for web/*.py

* Add missing Python modules required for web/*.py. [Jean-Baptiste Maillet]

* Merge pull request #176 from jbmaillet/pip_requirements_add_missing. [Alexandre Dulaunoy]

  Add some missing requirements, keeping docs in sync

* Add some missing requirements, keeping docs in sync. [Jean-Baptiste Maillet]

  irc is needed by bin/search_irc.py
  sleekxmpp is needed by bin/search_xmpp.py

  Update relevant documentation files, reordering python modules
  requirements when needed considering the root README.md as the
  reference.

* Merge pull request #173 from adulau/master. [Alexandre Dulaunoy]

  Fixed datetime.datetime issue with JSON

* Merge pull request #129 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfix for #172 of the master branch

* Merge pull request #171 from adulau/master. [Pidgey]

  Bug fix

* Merge pull request #128 from PidgeyL/master. [Alexandre Dulaunoy]

  re-add import that was accidentally removed

* Merge pull request #170 from adulau/master. [Alexandre Dulaunoy]

  Many fixes

* Merge pull request #127 from PidgeyL/master. [Alexandre Dulaunoy]

  Plug-in manager fixes, updates etc

* Error handling on date issues. [PidgeyL]

* Update the documentation to explain the plugins.txt error. [PidgeyL]

* Bugfix for #172 of the master branch. [PidgeyL]

* Re-add import that was accidentally removed. [PidgeyL]

* Review imports. [PidgeyL]

* Fix missing changes. [PidgeyL]

* Merge branch 'mattoufoutu-master' [PidgeyL]

* Merge branch with @mattoufoutu. [PidgeyL]

* Convert datetime objects to string when dumping db. [MatToufoutu]

* Convert datetime objects before output + pretty print json when doing free search. [MatToufoutu]

* Make date parsing in webui compatible with db datetime objects. [MatToufoutu]

* CurrentTimeFilter is no longer used. [MatToufoutu]

* Flask.ext notation is deprecated, use real package name instead. [MatToufoutu]

* Remove unused imports. [MatToufoutu]

* When running external scripts, use same interpreter as the current one. [MatToufoutu]

* Dates can now be formatted without using a custom filter as they are datetime objects. [MatToufoutu]

* Merge branch 'master' of git://github.com/cve-search/cve-search. [MatToufoutu]

* Merge pull request #168 from gitter-badger/gitter-badge. [Alexandre Dulaunoy]

  Add a Gitter chat badge to README.md

* Add Gitter badge. [The Gitter Badger]

* Merge pull request #167 from adulau/master. [Alexandre Dulaunoy]

  Many updates and bug fixes in the plug-ins

* Merge pull request #126 from PidgeyL/master. [Alexandre Dulaunoy]

  Add plug-in features, bugfixes and update documentation

* Merge pull request #125 from PidgeyL/master. [Alexandre Dulaunoy]

  Features and fixes

* Merge pull request #124 from PidgeyL/master. [Alexandre Dulaunoy]

  javascript/jquery bugfix

* Merge pull request #123 from PidgeyL/master. [Alexandre Dulaunoy]

  bugfix

* Merge pull request #122 from PidgeyL/master. [Alexandre Dulaunoy]

  Compatibiliy bugfix for Flask-PyMongo

* Dates can't be implicitely converted to strings, convert explicitely. [Mathieu Deous]

* Make all ./sbin/* scripts executable. [Mathieu Deous]

* Make all ./bin/* scripts executable. [Mathieu Deous]

* Merge branch 'master' of https://github.com/cve-search/cve-search. [Mathieu Deous]

* Merge pull request #162 from maximilianhuber/fix/repairReadmeExamples. [Alexandre Dulaunoy]

  fix(README): examlary calls were broken, i.e. were prefixed by `./python3.3`

* Fix(README): examlary calls were broken, i.e. were prefixed by `./python3.3` [maximilianhuber]

* Merge branch 'master' of https://github.com/cve-search/cve-search. [Mathieu Deous]

* Merge upstream. [Mathieu Deous]

* Create .gitignore file and configure to not track files/folders that shouldn't be. [MatToufoutu]

* Merge branch 'master' of https://github.com/cve-search/cve-search. [MatToufoutu]

* Ignore timezone when parsing date. [Mathieu Deous]

* Fix mistake when handling last modified date. [Mathieu Deous]

* Merge upstream changes. [Mathieu Deous]

* Get last-modified header from new response object. [Mathieu Deous]

* Merge branch 'master' of https://github.com/cve-search/cve-search into merge-upstream. [Mathieu Deous]

  Conflicts:
  	sbin/db_mgmt.py
  	sbin/db_mgmt_capec.py
  	sbin/db_mgmt_cpe_dictionary.py
  	sbin/db_mgmt_cwe.py
  	sbin/db_mgmt_d2sec.py
  	sbin/db_mgmt_vendorstatements.py
  	sbin/db_mgmt_vfeed.py
  	web/index.py
  	web/minimal-web.py
  	web/static/js/custom/scripts.js

* Force date conversion to string. [Mathieu Deous]

* Merge branch 'master' of github.com:mattoufoutu/cve-search. [Mathieu Deous]

* Fix datetimes display. [Mathieu Deous]

* Code format (PEP8 compliance) [Mathieu Deous]

* Missing semicolons. [Mathieu Deous]

* Inline variables where possible. [Mathieu Deous]

* Merge branch 'master' of https://github.com/wimremes/cve-search (forgotten changes: exit codes) [Mathieu Deous]

* Merge branch 'master' of https://github.com/wimremes/cve-search. [Mathieu Deous]

* Use datetime objects everywhere for last-modified field. [Mathieu Deous]

* ID for page manipulation. [PidgeyL]

* Allow plug-ins to pass dictionaries as well as the 'success boolean' [PidgeyL]

* Add error handling. [PidgeyL]

* Move pluginArgs to a function and fix **args missing in search. [PidgeyL]

* Move filters to a subpage and move javascript around. [PidgeyL]

* Change search format to list of CVEs instead of list of dictionaries with cve as ID. [PidgeyL]

* Bugfix for lists in settings. [PidgeyL]

* Sort plug-ins in plug-in manager. [PidgeyL]

* Sort functions for visibility. [PidgeyL]

* More checkings to prevent plug-in errors. [PidgeyL]

* More plug-in actions. [PidgeyL]

* Fix bug where only one instance gets loaded if multiple are given. [PidgeyL]

* Sort plug-ins. [PidgeyL]

* Make plugin bugs impact cve-search less. [PidgeyL]

* Bugfix with overlapping html id's and css rules. [PidgeyL]

* Add user settings and pass current_user to get_filters in plug-in manager. [PidgeyL]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Update documentation. [Pieter-Jan Moreels]

* Api only script. [Pieter-Jan Moreels]

* Remove plug-in related things from the minimal interface. [Pieter-Jan Moreels]

* Plug-in info on admin page. [PidgeyL]

* Add drop for plug-ins. [PidgeyL]

* Add 'change password' option in web interface. [PidgeyL]

* Javascript/jquery bugfix. [PidgeyL]

* Bugfix. [PidgeyL]

* Fix for #124 - right message when auth required. [PidgeyL]

* Remove forgotten debug code. [PidgeyL]

* Fix checkbox issue in filter settings. [PidgeyL]

* Allow 'bulk update' of one element. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #161 from mathrock/master. [Alexandre Dulaunoy]

  Fix bug in CPE parsing

* Fix bug in CPE parsing. [mathrock]

  The current CPE dictionary parsing didn't catch the end of the 'title'
  tag and would have extra data in the 'title' attribute of the CPE.

  As an example using CVE-2015-7183 from
  https://cve.circl.lu/api/cve/CVE-2015-7183:

  Currently shows up like this:
      {
        "id": "cpe:2.3:a:mozilla:firefox:41.0.2",
        "title": "Mozilla Firefox 41.0.2\n    \n      Vendor"
      },

  Should be:
      {
        "id": "cpe:2.3:a:mozilla:firefox:41.0.2",
        "title": "Mozilla Firefox 41.0.2"
      },

* Merge pull request #159 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes and updates

* Merge pull request #121 from PidgeyL/master. [Alexandre Dulaunoy]

  Small bugfixes and plug-in features

* Add compatibility bugfix for Flask-PyMongo version 4.x. [PidgeyL]

* Added sample for plugin.txt. [PidgeyL]

* Bugfixes. [PidgeyL]

* Bugfix for dictionaries. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* MITRE now serves the files in TLS (config updated) [Alexandre Dulaunoy]

* MITRE now serves the files in TLS (config updated) [Alexandre Dulaunoy]

* Merge pull request #120 from PidgeyL/master. [Alexandre Dulaunoy]

  Several updates and fixes in both index.py and cpeList.py

* Merge pull request #154 from adulau/master. [Alexandre Dulaunoy]

  Fix #147

* Merge pull request #146 from adulau/master. [Alexandre Dulaunoy]

  Replace syslog modules to logging module (to support Windows)

* Merge pull request #145 from adulau/master. [Alexandre Dulaunoy]

  Major web interface clean-up + some fixes for the minimal part

* Merge pull request #140 from adulau/master. [Alexandre Dulaunoy]

  Bug fix: search template must be minimal

* Give more options to functions. [PidgeyL]

* Show reasons for plug-in failure. [PidgeyL]

* Bugfix for dicts in p_addToList. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Fix #147. [Alexandre Dulaunoy]

* Update copyrights. [PidgeyL]

* Merge pull request #120 from PidgeyL/pluginmanager. [Pidgey]

  extend gitignore

* .gitignore indexdir. [PidgeyL]

* Git ignore .gitignore. [PidgeyL]

* Merge pull request #119 from PidgeyL/pluginmanager. [Pidgey]

  Pluginmanager

* Move the 'seen' functionality to its own plug-in. [PidgeyL]

* Bugfix in adding entries. [PidgeyL]

* Remove print(ex) [PidgeyL]

* Word-wrap pre & add padding. [PidgeyL]

* Add functionality of subpages. [PidgeyL]

* Add initial database search for plug-ins. [PidgeyL]

* Remove custom files from .gitignore. [PidgeyL]

* Add .gitignore for developer ease. [PidgeyL]

* Move MISP to a plug-in. [PidgeyL]

* New plug-in feature. [PidgeyL]

* Bugfixes, error handling and new function. [PidgeyL]

* New plug-in manager features + fix function names. [PidgeyL]

* Remove bookmarks & error handling. [PidgeyL]

* Initial commit plugin manager. [PidgeyL]

* Fix absolute/relative path issue. [PidgeyL]

* Finish moving all statusses to the status file. [PidgeyL]

* Add statusses of login to statusses.js. [PidgeyL]

* Merging more responses to statusses.js. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Replace syslog modules to logging module (to support Windows) [Alexandre Dulaunoy]

  This is just a quick replacement of syslog to support Windows
  platform. Potential fix for #143.

* Minimal option. [Alexandre Dulaunoy]

* Merge branch 'master' of https://github.com/adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #119 from PidgeyL/master. [Alexandre Dulaunoy]

  fix typo

* Minimal option added. [Alexandre Dulaunoy]

* Merge pull request #118 from PidgeyL/master. [Alexandre Dulaunoy]

  Some code optimization

* Bugfix and some updates in control panel. [Pieter-Jan Moreels]

* Update black-/whitelist import & export. [Pieter-Jan Moreels]

* Fix typo. [Pieter-Jan Moreels]

* Merge remote-tracking branch 'upstream/master' [Pieter-Jan Moreels]

* Merge branch 'master' of https://github.com/adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #137 from treyka/master. [Pidgey]

  correct misspelling of Wim's name

* Correct misspelling of Wim's name. [Trey Darley]

* Merge pull request #136 from adulau/master. [Alexandre Dulaunoy]

  vfeed fixes

* Merge pull request #135 from adulau/master. [Alexandre Dulaunoy]

  Added pytz in the requirements (required for MISP module) - Fix #134

* Merge pull request #131 from adulau/master. [Alexandre Dulaunoy]

  Handle exploit definition without ref element to fix #129

* Merge pull request #130 from adulau/master. [Alexandre Dulaunoy]

  doc and more

* Merge pull request #128 from adulau/master. [Alexandre Dulaunoy]

  cve-search branch for travis

* Merge pull request #127 from adulau/master. [Alexandre Dulaunoy]

  Python requirements >= 3.3

* Merge pull request #126 from adulau/master. [Alexandre Dulaunoy]

  Travis test added

* Merge pull request #125 from adulau/master. [Alexandre Dulaunoy]

  MISP support + bug fixes

* Bug fix: minimal template must be used for the search too. [Alexandre Dulaunoy]

* Merge pull request #117 from PidgeyL/master. [Alexandre Dulaunoy]

  Fix for #134 (master repo)

* Added pytz in the requirements (required for MISP module) - Fix #134. [Alexandre Dulaunoy]

* Complete master pages. [PidgeyL]

* Initial commit using master-pages. [PidgeyL]

* Shorten the update overview. [PidgeyL]

* Update search to search through vFeed IDs. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Handle exploit definition without ref element to fix #129. [Alexandre Dulaunoy]

  XML document of d2sec can have exploit without any reference.

* Merge pull request #116 from PidgeyL/master. [Alexandre Dulaunoy]

  add documentation in markdown & remove unused config variable

* Update requirements. [PidgeyL]

* Fix links. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Cve-search branch for travis. [Alexandre Dulaunoy]

* Python requirements >= 3.3. [Alexandre Dulaunoy]

* Travis build status added. [Alexandre Dulaunoy]

* Merge pull request #115 from Rafiot/travis. [Alexandre Dulaunoy]

  Add initial Travis file

* Add initial Travis file. [Raphaël Vinot]

* Merge pull request #114 from PidgeyL/master. [Alexandre Dulaunoy]

  bugfix + new features

* Remove presentation (moved to separate repo) [PidgeyL]

* Remove unused variable. [PidgeyL]

* Add markdown documentation. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [Pieter-Jan Moreels]

* Update freetext to be mongo 3 compatible ( #124 ) [Pidgey]

* Merge pull request #119 from pchaigno/fix-paths-readme. [Alexandre Dulaunoy]

  Fix paths to scripts in README

* Fix path to scripts in README. [Paul Chaignon]

* Merge pull request #118 from adulau/master. [Alexandre Dulaunoy]

  jq example fixed

* Merge pull request #115 from adulau/master. [Alexandre Dulaunoy]

  -o option added - to group search query by OR clause

* Merge pull request #114 from adulau/master. [Alexandre Dulaunoy]

  Commit missing part to Fix #97

* Merge pull request #113 from adulau/master. [Alexandre Dulaunoy]

  Fixed #112

* Merge pull request #110 from adulau/master. [Alexandre Dulaunoy]

  Updated with the general logo, added the public cve-search demo site.

* Merge pull request #109 from adulau/master. [Alexandre Dulaunoy]

  Fix issue #113 when cvssList is emtpy

* Merge pull request #108 from adulau/master. [Alexandre Dulaunoy]

  Various updates and fixes

* Merge pull request #107 from adulau/master. [Alexandre Dulaunoy]

  Fix #97 - get index path from Configuration

* Merge pull request #106 from adulau/master. [Alexandre Dulaunoy]

  CWS and CAPEC support added

* Merge pull request #105 from adulau/master. [Alexandre Dulaunoy]

  Database abstraction layer added

* Merge pull request #104 from adulau/master. [Alexandre Dulaunoy]

  More DB abstraction

* Add pymisp requirement. [Pidgey]

* Remove unneeded vars. [Pieter-Jan Moreels]

* Undo accidental code commit. [Pieter-Jan Moreels]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Jq -r -> jq -c. [Alexandre Dulaunoy]

* Fix the Brucon presentation regarding #117. [Alexandre Dulaunoy]

* Add misp to updater. [PidgeyL]

* Allow searching on MISP info. [PidgeyL]

* Misp info on cve page. [PidgeyL]

* Misp database updater. [PidgeyL]

* Basic implementation of misp info. [PidgeyL]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* -o option added - to group search query by OR clause. [Alexandre Dulaunoy]

* Commit missing part to Fix #97. [Alexandre Dulaunoy]

* Fixed #112. [Alexandre Dulaunoy]

* Updated with the general logo, added the public cve-search demo site. [Alexandre Dulaunoy]

* Fix issue #113 when cvssList is emtpy. [Alexandre Dulaunoy]

* DbInfo fixed in minimal web interface. [Alexandre Dulaunoy]

* Output a meaningful message when Redis is not running. [Alexandre Dulaunoy]

* Merge pull request #112 from PidgeyL/master. [Alexandre Dulaunoy]

  bugfix + new features

* Bugfix for empty bulk operations. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Make db stats queryable via api. [PidgeyL]

* Fix #97 - get index path from Configuration. [Alexandre Dulaunoy]

  fulltext search client didn't use the configuration parameters
  to get the index path. This is now fixed.

* Fix ssl cert path issue. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Mininal web interface: menu clarified. [Alexandre Dulaunoy]

* Fixed CAPEC and CWE view for the minimal web interface. [Alexandre Dulaunoy]

* CWE internal link updated. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #111 from PidgeyL/master. [Alexandre Dulaunoy]

  Missed links on minimal.py

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #110 from PidgeyL/master. [Alexandre Dulaunoy]

  CWE & CAPEC Browser

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #108 from PidgeyL/master. [Alexandre Dulaunoy]

  urgent bugfixes

* Merge pull request #107 from PidgeyL/master. [Alexandre Dulaunoy]

  finalizing the database layer

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #106 from PidgeyL/master. [Alexandre Dulaunoy]

  Updates + bugfixes

* Merge pull request #103 from adulau/master. [Alexandre Dulaunoy]

  Various updates and fixes

* Merge pull request #102 from adulau/master. [Alexandre Dulaunoy]

  Exploit databased added in cve-search

* Merge pull request #101 from adulau/master. [Alexandre Dulaunoy]

  Minor fixes

* Merge pull request #100 from adulau/master. [Alexandre Dulaunoy]

  No more default CVSS value when no CVSS are set for a CVE.

* Merge pull request #99 from adulau/master. [Alexandre Dulaunoy]

  Fix the NIST issue where NVD data feed is only accesible in gzip format.

* Merge pull request #96 from adulau/master. [Alexandre Dulaunoy]

  Remove _id from ranking output

* Merge pull request #95 from adulau/master. [Alexandre Dulaunoy]

  Fix #89 following

* Merge pull request #94 from adulau/master. [Alexandre Dulaunoy]

  CVSS float issue fixed in dump and JSON output for CPE search

* Merge pull request #91 from adulau/master. [Alexandre Dulaunoy]

  Initial version of a CVE converter to asciidoc

* Merge pull request #90 from adulau/master. [Alexandre Dulaunoy]

  Db layers changed from PJ merged

* Merge pull request #86 from adulau/master. [Alexandre Dulaunoy]

  API update

* Merge pull request #83 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes

* Merge pull request #81 from adulau/master. [Alexandre Dulaunoy]

  Various updates and fixes

* Merge pull request #80 from adulau/master. [Alexandre Dulaunoy]

  Updates + new NIST ref database + MS bulleting database

* Merge pull request #77 from adulau/master. [Alexandre Dulaunoy]

  Web interface updates and bug fixes

* Merge pull request #76 from adulau/master. [Alexandre Dulaunoy]

  Web interface updates

* Merge pull request #73 from adulau/master. [Alexandre Dulaunoy]

  Proxy support added + browser fixed

* Merge pull request #72 from adulau/master. [Alexandre Dulaunoy]

  Various updates

* View last update in web interface. [PidgeyL]

* Log updates. [Pieter-Jan Moreels]

* Missed links on minimal.py. [PidgeyL]

* Add browser to minimal. [PidgeyL]

* Link CAPEC from within CVE. [PidgeyL]

* Implementation CAPEC and CWE browsing. [PidgeyL]

* Initial commit cwe. [PidgeyL]

* Add minimal updater function. [Pieter-Jan Moreels]

* Bugfixes. [PidgeyL]

* Missed in last commit. [Pieter-Jan Moreels]

* Final database abstraction. [Pieter-Jan Moreels]

* More database layer abstracton. [Pieter-Jan Moreels]

* More abstraction. [Pieter-Jan Moreels]

* Bugfix + more abstraction. [Pieter-Jan Moreels]

* Fix typo. [Pieter-Jan Moreels]

* More database stuff. [PidgeyL]

* Cleaning-up and bugfixes. [PidgeyL]

* Bugfix. [PidgeyL]

* Bugfix. [PidgeyL]

* Bugfix. [PidgeyL]

* More database abstraction. [Pieter-Jan Moreels]

* More database abstraction. [Pieter-Jan Moreels]

* Reduce code size. [Pieter-Jan Moreels]

* Merge remote-tracking branch 'upstream/master' [Pieter-Jan Moreels]

* Db_mgmt_exploitdb.py: verbose mode added. [Alexandre Dulaunoy]

* Merge pull request #105 from PidgeyL/master. [Alexandre Dulaunoy]

  More database layer abstraction + initial starring

* Bugfix file selector. [Pieter-Jan Moreels]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Merge pull request #113 from tunkaflux/patch-3. [Pidgey]

  Small bugfix

* Small bugfix. [laurensv]

  This fixes:

  Starting capec
  Traceback (most recent call last):
    File "/home/laurens/Source/cve-search/sbin/db_mgmt_capec.py", line 172, in <module>
      i = dbLayer.getLastModified('capec')
  NameError: name 'dbLayer' is not defined
  capec has 463 elements (0 update)

  When doing '''python3 ./db_updater.py -c -i -v'''

* More db layer abstraction + bugfix import/export. [PidgeyL]

* More database layer abstraction. [PidgeyL]

* Added bookmarks page. [Pieter-Jan Moreels]

* Bugfixes. [PidgeyL]

* Merge. [PidgeyL]

* Number of collections updated. [Alexandre Dulaunoy]

* Exploit database added. [Alexandre Dulaunoy]

* Exploit database import added in configuration. [Alexandre Dulaunoy]

* First version of exploit database import script. [Alexandre Dulaunoy]

  The script import the exploit database into a new database exploitdb.

  The link between the exploitdb id and the cve will be done with the
  NIST ref database.

* Cleanup. [Alexandre Dulaunoy]

* Fail safe if content-type is not gzip. [Alexandre Dulaunoy]

* No more default CVSS value when no CVSS are set for a CVE. [Alexandre Dulaunoy]

  This should fix #93.

  As the default CVSS feature seems not to be used, it will be removed
  too.

* Fetch compressed NIST cvedb files only. Fix #98. [Alexandre Dulaunoy]

* NIST vendor statement not more available in uncompressed format. [Alexandre Dulaunoy]

* GetFile method can download compressed files via compressed argument. [Alexandre Dulaunoy]

  default (False) is to fetch uncompressed file.

  Related to issue #98

* Only fetch NIST dump in gzip format when populating  due to: [Alexandre Dulaunoy]

  "Effective October 16, 2015 the XML data feeds will no longer be
  available for download in an uncompressed format."

  https://nvd.nist.gov/Data-Feeds/datafeedinfo

  Reported by @Grazfather - Fix #98

* More database stuff. [PidgeyL]

* More database layer stuff. [PidgeyL]

* Bugfix. [Pieter-Jan Moreels]

* Bugfix. [Pieter-Jan Moreels]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Pres added. [Alexandre Dulaunoy]

* Remove _id from ranking output. [Alexandre Dulaunoy]

* Fix #89 following. [Alexandre Dulaunoy]

  https://github.com/maxcountryman/flask-login/issues/230

* Show bookmarks in index.html. [PidgeyL]

* Database abstraction. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Bugfix. [Pieter-Jan Moreels]

* Merge pull request #111 from tunkaflux/patch-2. [Pidgey]

  Small bugfix

* Small bugfix. [laurensv]

  Small bugfix to import :) This fixes:

  Starting redis-cache-cpe
  redis-cache-cpe updated
  Starting d2sec
  Traceback (most recent call last):
    File "/home/laurens/Source/cve-search/sbin/db_mgmt_d2sec.py", line 22, in <module>
      import DatabaseLayer as dbLayer
  ImportError: No module named 'DatabaseLayer'
  d2sec has 246 elements (0 update)

* Initial commit starring. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* CVSS casting to float. [Alexandre Dulaunoy]

* JSON output added to CPE search. [Alexandre Dulaunoy]

* Initial version of a CVE converter to asciidoc. [Alexandre Dulaunoy]

  The asciidoc file can be converted to any format supported by
  an asciidoc parser. The CVE is fetched via the standard web API
  (so it can be used in standalone mode).

  You can generate an HTML file from the asciidoc:

  python3 cve_doc.py  -c CVE-2015-0003 | asciidoctor - >test.html

* Merge pull request #99 from PidgeyL/master. [Alexandre Dulaunoy]

  Initial work on Database Layer remodelling

* More database layer abstraction. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Merge pull request #110 from tunkaflux/patch-1. [Pidgey]

  Update defaultHead.html

* Update defaultHead.html. [laurensv]

  This fixes the 404 error message in the logs when IE tries to load that Javascript file.

* More database abstraction. [PidgeyL]

* Remove unused imports & bug. [PidgeyL]

* More database layer abstraction. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Bugfix. [PidgeyL]

* More database layer abstraction. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Bugfix. [PidgeyL]

* Remove unneeded imports, vars and the like. [PidgeyL]

* Bugfix: missing import. [PidgeyL]

* Bugfix search page minimal. [PidgeyL]

* Fully implement dblayer in minimal.py. [PidgeyL]

* Complete dblayer in index.py. [PidgeyL]

* Fix merge. [PidgeyL]

* Bugfix with typos. [PidgeyL]

* Bugfixes. [PidgeyL]

* Typo fix. [PidgeyL]

* Bugfix database layer None Type. [PidgeyL]

* More database layer abstraction. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Dump last 30 entries in JSON (via the API). [Alexandre Dulaunoy]

  API /api/last dump in JSON the last 30 updated entries of CVE.
  The entries are expanded including CPE, CAPEC and CWE.

* Remove ObjectID from last entries dump. [Alexandre Dulaunoy]

* More database layer abstraction. [PidgeyL]

* More database layer abstraction. [PidgeyL]

* More database abstraction. [PidgeyL]

* More database abstraction. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Merge pull request #98 from psychedelys/master. [Alexandre Dulaunoy]

  MS feed seem to be only available as xlsx and not anymore as xls

* Now seem to be only available as xlsx. [psychedelys]

* Merge pull request #97 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes

* Bugfix html output. [PidgeyL]

* Debug debug output ;) [PidgeyL]

* Debug debug output ;) [PidgeyL]

* Merge pull request #96 from PidgeyL/master. [Alexandre Dulaunoy]

  Little tweaks

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #95 from psychedelys/master. [Alexandre Dulaunoy]

  move sme './tmp/' to config file.

* Shebang standardisation. [psychedelys]

* Merge remote-tracking branch 'upstream/master' [psychedelys]

* Merge pull request #94 from psychedelys/master. [Alexandre Dulaunoy]

  fetch with std methods

* Move the './tmp/' from some script to a config value. [psychedelys]

* Using the Configuration.getFile instead of urlopen for the proxy if needed. [psychedelys]

* Lxml requirement added. [Alexandre Dulaunoy]

* Remove prints and add more info to default page. [PidgeyL]

* Better overview failed indexes. [PidgeyL]

* Minimal getref method to list all known NIST references. [Alexandre Dulaunoy]

* Redis databases documented. [Alexandre Dulaunoy]

* Verbose mode added as an option. [Alexandre Dulaunoy]

* Db_mgmt_ref.py added in the updater (Redis required) [Alexandre Dulaunoy]

* First working version of the NIST ref importer into Redis (db 12) [Alexandre Dulaunoy]

* Redis RefDB - getRedisRefConnection function added. [Alexandre Dulaunoy]

* Redis database 12 is reserved for RefDB. [Alexandre Dulaunoy]

* Microsoft bulletins added in the documentation. [Alexandre Dulaunoy]

* Merge pull request #92 from chervaliery/master. [Alexandre Dulaunoy]

  Add MS-Bulletin

* Add MS-Bulletin. [Yoann Chevalier]

  Get ms-bulletin from Microsoft and add them in the collection 'ms'
  New requirement xlrd to parse xls

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #91 from PidgeyL/master. [Alexandre Dulaunoy]

  Fulltext search in minimal + fix typo in doc

* Merge pull request #90 from PidgeyL/master. [Alexandre Dulaunoy]

  documentation for fulltext search

* Mgmt ref downloader added. [Alexandre Dulaunoy]

* Initial commit database layer. [PidgeyL]

* Fix typo in documentation. [Pieter-Jan]

* Add full text search to minimal. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #89 from PidgeyL/master. [Alexandre Dulaunoy]

  bugfixes and remove unneeded code

* Merge pull request #88 from PidgeyL/master. [Alexandre Dulaunoy]

  continuation POST to AJAX + important bugfix

* Merge pull request #87 from PidgeyL/master. [Alexandre Dulaunoy]

  replace posts with ajax requests

* Merge pull request #86 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes

* Bugfix clearing fields after adding item to black/whitelist. [PidgeyL]

* Documentation for fulltext search. [PidgeyL]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Bugfix. [Pieter-Jan]

* Fulltext search on database. [PidgeyL]

* Remove unneeded class. [PidgeyL]

* Continuation POST to AJAX + important bugfix. [PidgeyL]

* Fix incomplete commit. [PidgeyL]

* Replace posts with ajax requests. [PidgeyL]

* Update. [PidgeyL]

* Merge pull request #85 from PidgeyL/master. [Alexandre Dulaunoy]

  vFeed info in cvesfor

* Fixed pull request #84 - test case of proxy configuration. [Alexandre Dulaunoy]

* Merge pull request #84 from psychedelys/master. [Alexandre Dulaunoy]

  Bugfix on pager + added the http proxy support.

* Implementation http proxy for db_mgmt process. [Psychedelys]

* Bugfix: broken pager. [Psychedelys]

* Merge remote-tracking branch 'cherval/capec-structure' [Alexandre Dulaunoy]

* Change the CAPEC structure. [Yoann Chevalier]

  The summary, prerequisites and solutions were saved in array. This was useless, a simple text field is more convenient.

* Merge pull request #69 from adulau/master. [Alexandre Dulaunoy]

  Various fixes, updates and improvement

* Merge pull request #83 from PidgeyL/master. [Alexandre Dulaunoy]

  Initial commit of moving functions like adding/removing items from white/blacklists to AJAX requests

* Merge pull request #82 from PidgeyL/master. [Alexandre Dulaunoy]

  bugfixes

* Merge pull request #81 from PidgeyL/master. [Alexandre Dulaunoy]

  seen CVEs per user

* Merge pull request #106 from PidgeyL/development. [Pieter-Jan]

  several bugfixes

* Several bugfixesé. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Merge pull request #105 from PidgeyL/development. [Pieter-Jan]

  initial commit moving funtions to ajax

* Initial commit moving funtions to ajax. [PidgeyL]

* Bugfix for pymongo3. [PidgeyL]

* Mark linked items. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge branch 'master' of github.com:wimremes/cve-search. [Alexandre Dulaunoy]

* Merge pull request #68 from timeemit/authentication. [Alexandre Dulaunoy]

  Mongo authentication

* Provide auth credentials on when provided. [TimeEmit]

* URL Escape the username and password. [TimeEmit]

* Mongo authentication. [TimeEmit]

* Merge pull request #67 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes and initial code for NIST reference

* Merge pull request #66 from adulau/master. [Alexandre Dulaunoy]

  Enhanced output of the web admin part

* Merge pull request #65 from adulau/master. [Alexandre Dulaunoy]

  Bug fix

* Merge pull request #63 from adulau/master. [Alexandre Dulaunoy]

  Fix #62

* Merge pull request #61 from adulau/master. [Alexandre Dulaunoy]

  Various updates

* Merge pull request #60 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes

* Merge pull request #59 from adulau/master. [Alexandre Dulaunoy]

  Many updates

* Merge pull request #54 from adulau/master. [Alexandre Dulaunoy]

  Various fixes and updates

* Merge pull request #52 from adulau/master. [Alexandre Dulaunoy]

  CPE 2.2 and 2.3 support - XMPP support extended

* Merge pull request #51 from adulau/master. [Alexandre Dulaunoy]

  XMPP client updated

* Merge pull request #50 from adulau/master. [Alexandre Dulaunoy]

  Major update of the directory structure

* Merge pull request #49 from adulau/master. [Alexandre Dulaunoy]

  Web JSON API added + Flush database option + various fixes

* Merge pull request #46 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes

* Merge pull request #44 from adulau/master. [Alexandre Dulaunoy]

  Many updates

* Merge pull request #42 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes and updates

* Merge pull request #40 from adulau/master. [Alexandre Dulaunoy]

  Many fixes and PEP-8 cleanup

* Merge pull request #38 from adulau/master. [Alexandre Dulaunoy]

  Merge of downstream and upstream pulls + fixes

* _id removed from the return list. [Alexandre Dulaunoy]

* Help clarified for the top terms used. [Alexandre Dulaunoy]

* Bug fix: Exit if the Whoosh index is locked. [Alexandre Dulaunoy]

* Help regarding full indexing added (0 to index all) [Alexandre Dulaunoy]

* Empty rankings are discarded. [Alexandre Dulaunoy]

* Don't add ranking if ranking is empty. [Alexandre Dulaunoy]

* -l option added to limit the number of elements (default: unlimited) [Alexandre Dulaunoy]

* Merge pull request #80 from PidgeyL/master. [Alexandre Dulaunoy]

  Fix progress bar issue

* Merge pull request #104 from PidgeyL/development. [Pieter-Jan]

  Development

* Completion seen/unseen. [PidgeyL]

* Implementation mark seen. [PidgeyL]

* Remove test data. [PidgeyL]

* Implementation 'seen' on opened cves. [PidgeyL]

* Bugfix placeholder _dummy_ [PidgeyL]

* Initial commit 'seen' status. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* NIST CVE Reference Key/Maps added. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #79 from PidgeyL/master. [Alexandre Dulaunoy]

  Console output feature for the web interface

* NIST Reference Map URL added. [Alexandre Dulaunoy]

* Merge pull request #103 from PidgeyL/development. [Pieter-Jan]

  remove progress bar from console output

* Remove progress bar from console output. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #78 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfix by @rlintu

* Merge pull request #77 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfix

* Merge pull request #76 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Error Handling

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #75 from PidgeyL/master. [Alexandre Dulaunoy]

  searching for CVEs case insensitive

* Import cpeother database in Redis cache (-o option added) [Alexandre Dulaunoy]

* Merge pull request #74 from PidgeyL/master. [Alexandre Dulaunoy]

  Better pager

* Merge pull request #102 from PidgeyL/development. [Pieter-Jan]

  Development

* Enhance output console. [PidgeyL]

* Output of console in admin pannel. [PidgeyL]

* Include vfeed info to cvesfor, allowing tools using the api more options. [PidgeyL]

* Merge pull request #101 from PidgeyL/development. [Pieter-Jan]

  Bugfix by @rlintu

* Bugfix by @rlintu. [PidgeyL]

* Merge pull request #100 from PidgeyL/development. [Pieter-Jan]

  bugfix empty collections

* Bugfix empty collections. [PidgeyL]

* Merge pull request #99 from PidgeyL/development. [Pieter-Jan]

  Development

* Remove excess code. [PidgeyL]

* #87 error handling on no/bad internet connection and invalid urls. [PidgeyL]

* Merge pull request #96 from PidgeyL/development. [Pieter-Jan]

  make searching for cves case insensitive

* Make searching for cves case insensitive. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #73 from PidgeyL/development. [Alexandre Dulaunoy]

  fix javascript pager bug

* Merge pull request #72 from PidgeyL/master. [Alexandre Dulaunoy]

  Extend pager to browe faster

* Merge pull request #71 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Bugfixes

* Merge pull request #95 from PidgeyL/development. [Pieter-Jan]

  update better pager

* Update better pager. [PidgeyL]

* Merge pull request #94 from PidgeyL/development. [Pieter-Jan]

  fix javascript pager bug

* Fix javascript pager bug. [PidgeyL]

* Merge pull request #93 from PidgeyL/development. [Pieter-Jan]

  pager update #21

* Pager update #21. [PidgeyL]

* Gracious shutdown. [PidgeyL]

* Remove unused imports. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Https URLs. [Alexandre Dulaunoy]

* /r/ is used from client side (JS/POST) and Bot via GET. [Alexandre Dulaunoy]

* /r/ can be GET request too. [Alexandre Dulaunoy]

* Initial commit irc search bot. [PidgeyL]

* Abstract query code for esier implementation. [PidgeyL]

* Fix structure change bug. [PidgeyL]

* Merge upstream. [PidgeyL]

* (temp) Bug fix: replace HTML/XML encoded value of "!" with nothing. [Alexandre Dulaunoy]

  Like "joomla%21" -> "joomla"

  Maybe this needs to be reviewed at the import process to ensure
  the XML elements encoded are properly encoded also in the Redis cache.

* About box added. [Alexandre Dulaunoy]

* Merge pull request #69 from PidgeyL/master. [Alexandre Dulaunoy]

  File structure

* Merge pull request #92 from PidgeyL/development. [Pieter-Jan]

  Development

* Encoding and decoding in webpages. [PidgeyL]

* Update "current supported commands" list. [PidgeyL]

* Fix bug caused by structure update. [PidgeyL]

* Merge pull request #91 from PidgeyL/development. [Pieter-Jan]

  file structure update

* File structure update. [PidgeyL]

* Fix imports. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Javascript fixed to not get undeclared elements. [Alexandre Dulaunoy]

* Merge pull request #68 from PidgeyL/master. [Alexandre Dulaunoy]

  Duplicate code removal

* Merge pull request #67 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Bugfixes

* Satisfy pyflakes. [PidgeyL]

* Extract functions to avoid duplicate code. [PidgeyL]

* Test padding. [PidgeyL]

* Add cpe 2.3 to 2.2 to api. [PidgeyL]

* Bugfix for 'empty collection' [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Minimal navbar updated. [Alexandre Dulaunoy]

* Linked minimal template added. [Alexandre Dulaunoy]

* Linked minimal added. [Alexandre Dulaunoy]

* Minimal templates added. [Alexandre Dulaunoy]

* First minimal web interface for cve-search. [Alexandre Dulaunoy]

* Merge pull request #66 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Bugfixes

* Merge pull request #90 from PidgeyL/development. [Pieter-Jan]

  Development

* Api for backwards translation. [PidgeyL]

* Backwards translation of CPE 2.3 to 2.2. [PidgeyL]

* Backwards translation of CPE 2.3 to 2.2. [PidgeyL]

* Initial commit backwards translation. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Merge pull request #89 from PidgeyL/development. [Pieter-Jan]

  Development

* Fix 10.1 on complete impact. [PidgeyL]

* Cpe 2.2 to 2.3 api url. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Fix #65. [Alexandre Dulaunoy]

* Merge pull request #64 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Error Handling

* Fix path issue. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Merge pull request #88 from PidgeyL/development. [Pieter-Jan]

  Error Handling

* Error Handling. [PidgeyL]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Skip on empty collections. [Alexandre Dulaunoy]

* Merge pull request #63 from PidgeyL/master. [Alexandre Dulaunoy]

  Error Handling

* Make api understand both cpe formats. [PidgeyL]

* Api plugin to get cves for cpe. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #62 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Bugfixes

* XMPP<->API browse, search and get options added. [Alexandre Dulaunoy]

* Merge pull request #86 from PidgeyL/development. [Pieter-Jan]

  Development

* Add path for admin (ease of access) [PidgeyL]

* Error handling. [PidgeyL]

* Merge pull request #85 from PidgeyL/development. [Pieter-Jan]

  add keyword feature to commandline

* Add keyword feature to commandline. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #61 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes + new features

* -l and -f are conflictual. [Alexandre Dulaunoy]

* Merge pull request #60 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Bugfixes

* Merge pull request #84 from PidgeyL/development. [Pieter-Jan]

  Development + Bugfixes

* Allow adding keywords. [PidgeyL]

* Bugfix new cpe format redis cache. [PidgeyL]

* Bugfix redis cache. [PidgeyL]

* Change function names. [PidgeyL]

* Update cpe regex. [PidgeyL]

* Bugfix cpeold. [PidgeyL]

* Merge pull request #83 from PidgeyL/development. [Pieter-Jan]

  bugfix

* Bugfix. [PidgeyL]

* Bugfix new CPE. [PidgeyL]

* Merge pull request #82 from PidgeyL/test. [Pieter-Jan]

  Test

* Merge master. [PidgeyL]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Merge pull request #81 from PidgeyL/development. [Pieter-Jan]

  Development

* Fix merge. [PidgeyL]

* Bugfixes and CPE update. [PidgeyL]

* Bugfix for empty collection. [PidgeyL]

* Xmpp: -m option add to limit the range of elements. [Alexandre Dulaunoy]

* Search command removed. [Alexandre Dulaunoy]

  Search command removed was too buggy. The command will be added
  again when a clean API is available for the full-text search via
  the local indexer.

* Search ordered by Modified field. [Alexandre Dulaunoy]

* -4 option added to disable IPv6 connectivity (enabled by default) [Alexandre Dulaunoy]

* CVSS typo (CSS ->CVSS) in the table head. [Alexandre Dulaunoy]

* -f option explained - repopulate all cve-search collections. [Alexandre Dulaunoy]

* Merge pull request #57 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Bugfixes

* Update to new cpe format. [PidgeyL]

* Bugfix for empty collection. [PidgeyL]

* Test branch. [PidgeyL]

* Move file structure. [PidgeyL]

* CVSS sub score bugfix. [PidgeyL]

* Fix moving scripts to bin folder. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* API: HTTP GET method only. [Alexandre Dulaunoy]

* Bugfix for bug created in ff9389a3b68b2368c10ed31aa2073852b6064723. [PidgeyL]

* Bugfix with trying to decode strings. [PidgeyL]

* Bug fixed - f was out of scope. [Alexandre Dulaunoy]

* Condition fixed. [Alexandre Dulaunoy]

* -f option: drop metadata about download and force CVE new population. [Alexandre Dulaunoy]

* -f option added - drop all collections. [Alexandre Dulaunoy]

  The -f option is required when the datastore structure changed or
  new elements are supported by cve-search. As there is no specific
  user information in the database, if the data sources are available,
  no data should be lost. The import can take sometime.

* Change file structure. [PidgeyL]

* CVSS Sub scores added. [PidgeyL]

* Bugfix with trying to decode strings. [PidgeyL]

* Bugfix for bug created in ff9389a3b68b2368c10ed31aa2073852b6064723. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Minimal API documentation added. [Alexandre Dulaunoy]

* Redis clean-up : UTF-8 encoding at the library level. [Alexandre Dulaunoy]

* CAPEC collection added in the documentation. [Alexandre Dulaunoy]

* API: /api/search/<vendor>/<path:product> added. [Alexandre Dulaunoy]

* API: /api/browse and /api/browse/vendor added. [Alexandre Dulaunoy]

* Redis cache: ensure that responses are UTF-8 encoded. [Alexandre Dulaunoy]

* Merge pull request #55 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes

* Merge pull request #54 from PidgeyL/master. [Alexandre Dulaunoy]

  Development

* Merge pull request #80 from PidgeyL/development. [Pieter-Jan]

  change file structure for better overview

* Change file structure for better overview. [PidgeyL]

* Update 'last modified' after succesful script run + commenting. [PidgeyL]

* Bugzilla confirmed bugfix. [PidgeyL]

* Fix bad merge. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* JSON API /api/cve/<cveid> added. [Alexandre Dulaunoy]

* Do not expose ObjectID to getcve() and getcapec() [Alexandre Dulaunoy]

* Merge pull request #53 from PidgeyL/master. [Alexandre Dulaunoy]

  Development + Bugfixes

* Merge pull request #78 from PidgeyL/development. [Pieter-Jan]

  fix bad merge

* Fix bad merge. [PidgeyL]

* Merge pull request #77 from PidgeyL/development. [Pieter-Jan]

  Development

* Update merge. [PidgeyL]

* Initial commit cpe formalization. [PidgeyL]

* Remove vfeed prefix in web ui for better visibility. [PidgeyL]

* Automatically create clickable urls from vfeed urls. [PidgeyL]

* Fix bugzilla field. [PidgeyL]

* Re-arrange order so cpeOther isn't always one cycle later. [PidgeyL]

* Merge update. [PidgeyL]

* Merge update. [PidgeyL]

* Add placeholder to allow merge. [PidgeyL]

* Update linked items with new vFeed format. [PidgeyL]

* Update web ui for new vFeed sorting. [PidgeyL]

* Grouping vFeed maps. [PidgeyL]

* Black/whitelisting on target hard/software. [PidgeyL]

* Remove useless var + Copy2Clip text. [PidgeyL]

* Merge upstream. [PidgeyL]

* Remove the phantom getBlackRules - maybe associated functions need to be removed too. [Alexandre Dulaunoy]

* Merge pull request #52 from Rafiot/PEP8. [Alexandre Dulaunoy]

  Make PEP8 happy.

* Make PEP8 happy. [Raphaël Vinot]

* Merge pull request #75 from PidgeyL/development. [Pieter-Jan]

  bugfixes

* Fix html decoding title. [PidgeyL]

* Fix blacklistrules. [PidgeyL]

* Fix html encoding. [PidgeyL]

* Merge pull request #74 from PidgeyL/development. [Pieter-Jan]

  Development

* Iconize button + replace. [PidgeyL]

* Update bootstrap js. [PidgeyL]

* Update bootstrap. [PidgeyL]

* Temp bugfix with path. [PidgeyL]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #51 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes + new features

* Sorting of vfeed data. [PidgeyL]

* Merge pull request #73 from PidgeyL/development. [Pieter-Jan]

  Development

* Remove abundant files. [PidgeyL]

* Abstract default head for easier updating. [PidgeyL]

* Initial commit #8. [PidgeyL]

* Merge pull request #72 from PidgeyL/development. [Pieter-Jan]

  fix math + add more info

* Fix math + add more info. [PidgeyL]

* Merge pull request #71 from PidgeyL/development. [Pieter-Jan]

  Development

* Extra database info. [PidgeyL]

* Add white-/blacklist info to admin pannel. [PidgeyL]

* Merge branch 'development' of http://github.com/pidgeyl/cve-search into development. [PidgeyL]

* Bugfixes upsert. [PidgeyL]

* Minimal database stats. [PidgeyL]

* Stats for linked cves. [PidgeyL]

* Merge pull request #70 from PidgeyL/development. [Pieter-Jan]

  Development + Bugfixes

* Bugfixes upsert. [PidgeyL]

* Minimal database stats. [PidgeyL]

* Stats for linked cves. [PidgeyL]

* Merge pull request #69 from PidgeyL/development. [Pieter-Jan]

  Development

* Fix the library import - (TODO: name shadowing still to be fixed) [Alexandre Dulaunoy]

* Cleanup - name shadowing. [Alexandre Dulaunoy]

* Import lib.CVEs. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:wimremes/cve-search. [Alexandre Dulaunoy]

  Conflicts:
  	dump_last.py

* Merge pull request #37 from mattoufoutu/fixes. [Alexandre Dulaunoy]

  multiple fixes

* Avoid name shadowing with builtins and custom vars. [Mathieu Deous]

* Create the UserNotFoundError exception class. [Mathieu Deous]

* Stop messing with sys.path, make lib a read package. [Mathieu Deous]

* Remove unexpected argument when calling BulkUpsertOperation.update() [Mathieu Deous]

* When fulltext indexing is enabled, subprocess' wait() method is not called. [Mathieu Deous]

* Merge pull request #36 from adulau/master. [Alexandre Dulaunoy]

  Various fixes and updates

* Merge pull request #35 from adulau/master. [Alexandre Dulaunoy]

  Various fixes and updates

* Merge pull request #33 from adulau/master. [Alexandre Dulaunoy]

  Important bugfix

* Merge pull request #31 from adulau/master. [Alexandre Dulaunoy]

  CAPEC support added, many bug fixes and improvement

* Merge pull request #30 from adulau/master. [Alexandre Dulaunoy]

  CAPEC support added + many bug fixes

* Merge pull request #29 from adulau/master. [Alexandre Dulaunoy]

  Various fixes, updates and improvement

* Merge pull request #28 from adulau/master. [Alexandre Dulaunoy]

  CAPEC support added + many bug fixes

* Merge pull request #27 from adulau/master. [Alexandre Dulaunoy]

  Various fixes and updates

* Merge pull request #25 from adulau/master. [Alexandre Dulaunoy]

  PBKDF2 support added

* Merge pull request #24 from adulau/master. [Alexandre Dulaunoy]

  Various fixes and updates

* Merge pull request #23 from adulau/master. [Alexandre Dulaunoy]

  Updates and bug fixes

* Merge pull request #22 from adulau/master. [Alexandre Dulaunoy]

  Updates

* Merge pull request #21 from adulau/master. [Alexandre Dulaunoy]

  Many updates

* Merge pull request #20 from adulau/master. [Alexandre Dulaunoy]

  Bug fixes

* Merge pull request #19 from adulau/master. [Alexandre Dulaunoy]

  Web view updates

* Merge pull request #18 from adulau/master. [Alexandre Dulaunoy]

  Fixes

* Merge pull request #17 from adulau/master. [Alexandre Dulaunoy]

  Configuration enhancement + various bug fixes

* Merge pull request #16 from adulau/master. [Alexandre Dulaunoy]

  Configuration enhancement

* Merge pull request #15 from adulau/master. [Alexandre Dulaunoy]

  Major sync

* Merge pull request #14 from adulau/master. [Alexandre Dulaunoy]

  CWE version updated + CPE references added

* Merge pull request #13 from adulau/master. [Wim Remes]

  Documentation updates and bug fixes in the full text search tool.

* Merge pull request #12 from adulau/master. [Wim Remes]

  Cleanup of db dump code + vfeed updates

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #50 from PidgeyL/development. [Alexandre Dulaunoy]

  Development

* Fix bug with dot (.) in path. [PidgeyL]

* Move table to separate html for easier modification. [PidgeyL]

* Move CVSS for better visibility. [PidgeyL]

* Took out milw0rm as it's not available anymore. [PidgeyL]

* CAPEC option added. [Alexandre Dulaunoy]

* Merge pull request #49 from PidgeyL/master. [Alexandre Dulaunoy]

  bugfix + new web feature

* Merge pull request #68 from PidgeyL/development. [Pieter-Jan]

  fix lowercase/uppercase issue

* Fix lowercase/uppercase issue. [PidgeyL]

* Merge pull request #67 from PidgeyL/development. [Pieter-Jan]

  Development

* Html encode/decode for url building. [PidgeyL]

* Bugfix vendorstatement. [PidgeyL]

* Initial commit linked cve's. [PidgeyL]

* Merge pull request #48 from PidgeyL/master. [Alexandre Dulaunoy]

  Important (stupid) bugs fixed

* Merge pull request #65 from PidgeyL/development. [Pieter-Jan]

  fixing some (stupid) bug

* Fixing some (stupid) bug. [PidgeyL]

* Merge pull request #47 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfix + Performance Increase

* Merge pull request #64 from PidgeyL/development. [Pieter-Jan]

  Development + Optimization

* Progress bar + bulk operations. [PidgeyL]

* Batch operations for speeding up intake. [PidgeyL]

* Merge pull request #63 from PidgeyL/development. [Pieter-Jan]

  bugfixes

* Bugfix. [PidgeyL]

* Bugfix after optimization. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #46 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfix + Code optimization

* Merge pull request #45 from PidgeyL/master. [Alexandre Dulaunoy]

  User friendlyness

* CAPEC output option added (-c) to db dump. [Alexandre Dulaunoy]

* -a option added - CAPEC output. [Alexandre Dulaunoy]

* Merge pull request #62 from PidgeyL/development. [Pieter-Jan]

  Bugfix + Performance Increase

* Optimization - Performance increase. [PidgeyL]

* Add bug with redhat_bugzilla. [PidgeyL]

* Merge pull request #61 from PidgeyL/development. [Pieter-Jan]

  Bugfix + Code optimization

* Bugfix for CPE lookup. [PidgeyL]

* Code optimization. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #44 from PidgeyL/master. [Alexandre Dulaunoy]

  Addition of CAPEC to the CVE info (webcomponent)

* CAPEC in get() function. [Alexandre Dulaunoy]

* Merge pull request #43 from PidgeyL/development. [Alexandre Dulaunoy]

  bugfixes + user friendlyness

* Merge pull request #42 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfix for missing CVSS-Time

* Merge pull request #41 from PidgeyL/master. [Alexandre Dulaunoy]

  Selectively turn on/off aditional feeds

* Merge pull request #59 from PidgeyL/development. [Pieter-Jan]

  collapsible option for multiple fields

* Collapsible option for multiple fields. [PidgeyL]

* Merge pull request #58 from PidgeyL/development. [Pieter-Jan]

  adding CAPEC to the web interface

* Adding CAPEC to the web interface. [PidgeyL]

* Merge pull request #57 from PidgeyL/development. [Pieter-Jan]

  Development

* Bugfix double expand (child-arent) [PidgeyL]

* Fix abundant css class. [PidgeyL]

* Missing css update. [PidgeyL]

* Semi-collapsed vuln-conf field for easy scrolling. [PidgeyL]

* Critical bugfix on unknown cwe. [PidgeyL]

* Merge pull request #55 from PidgeyL/development. [Pieter-Jan]

  bugfix for missing cvss-time

* Bugfix for missing cvss-time. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Add CAPEC entries even if CPE are not present in the CVE. [Alexandre Dulaunoy]

* CAPEC lookup added in the cve library. [Alexandre Dulaunoy]

* Getcapec per CWE id function added. [Alexandre Dulaunoy]

* Merge pull request #40 from PidgeyL/master. [Alexandre Dulaunoy]

  Minimum requirements for six

* Merge pull request #39 from PidgeyL/master. [Alexandre Dulaunoy]

  Enrich the database with more info

* Merge pull request #54 from PidgeyL/development. [Pieter-Jan]

  Development

* Selectively toggle on and off feeds. [PidgeyL]

* Initial commit allowing to turn off feeds. [PidgeyL]

* Merge pull request #53 from PidgeyL/development. [Pieter-Jan]

  update minimum requirements for six

* Update minimum requirements for six. [PidgeyL]

* Merge pull request #52 from PidgeyL/development. [Pieter-Jan]

  CVE aditional info

* Putting cvss time on the correct place. [PidgeyL]

* Adding access and impact to cve.html. [PidgeyL]

* Adding more CVE information to database (access & impact) [PidgeyL]

* Related_weakness index added in CAPEC. [Alexandre Dulaunoy]

* Merge pull request #38 from PidgeyL/master. [Alexandre Dulaunoy]

  enhancement for url's to different websites

* Merge pull request #50 from PidgeyL/development. [Pieter-Jan]

  URLs

* Make map_cve_scip_sciplink a url. [PidgeyL]

* Open references in new tabs. [PidgeyL]

* CAPEC import script added in the updater. [Alexandre Dulaunoy]

* Merge pull request #37 from PidgeyL/master. [Alexandre Dulaunoy]

  Adding software with CVE-Search

* Add software using cve-search. [PidgeyL]

* Addition of software using cve-search. [Pieter-Jan]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Sample configuration added. [Alexandre Dulaunoy]

* Default configuration removed. [Alexandre Dulaunoy]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #35 from chervaliery/master. [Alexandre Dulaunoy]

  New Feature : CAPEC import script

* Import of the CAPEC. [Yoann Chevalier]

* Import of the CAPEC. [Yoann Chevalier]

* Merge pull request #34 from PidgeyL/master. [Alexandre Dulaunoy]

  File chooser for web interface

* Merge pull request #49 from PidgeyL/development. [Pieter-Jan]

  config sample instead of config prevents overriding when pulling new rel...

* Config sample instead of config prevents overriding when pulling new release. [PidgeyL]

* Merge pull request #48 from PidgeyL/development. [Pieter-Jan]

  textiowrapper instead of stringio

* Textiowrapper instead of stringio. [PidgeyL]

* Merge pull request #47 from PidgeyL/development. [Pieter-Jan]

  #26 file chooser for import/export

* #26 file chooser for import/export. [PidgeyL]

* Db_fulltext: Indexdir is now configurable. [Alexandre Dulaunoy]

* Bug fixed: indexdir variable was not used. [Alexandre Dulaunoy]

* XML handler instantiated per file. [Alexandre Dulaunoy]

* Merge pull request #33 from PidgeyL/master. [Alexandre Dulaunoy]

  Remove unused imports

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Merge pull request #46 from PidgeyL/development. [Pieter-Jan]

  optimization

* Remove unused imports. [PidgeyL]

* Remove unused imports. [PidgeyL]

* Merge pull request #32 from PidgeyL/master. [Alexandre Dulaunoy]

  Optimization and enhancement black/whitelist

* Merge pull request #45 from PidgeyL/development. [Pieter-Jan]

  Enhancements + new features

* Remove duplicate code. [PidgeyL]

* Allow reading text files for removing + argparse. [PidgeyL]

* Allow reading text files for input + argparse. [PidgeyL]

* Update info. [PidgeyL]

* Merge pull request #44 from PidgeyL/development. [Pieter-Jan]

  Development

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #31 from PidgeyL/development. [Alexandre Dulaunoy]

  Documentation + Updating README

* Update documentation. [PidgeyL]

* Actualizing README. [PidgeyL]

* Spellcheck + update documentation. [PidgeyL]

* Merge pull request #30 from PidgeyL/master. [Alexandre Dulaunoy]

  Documentation + Optimization

* Merge pull request #43 from PidgeyL/development. [Pieter-Jan]

  Documentation + Optimization

* Update documentation. [PidgeyL]

* Update documentation. [PidgeyL]

* Relative path for fulltext indexer. [PidgeyL]

* Add cpeother to the updater script (runs only if initialized by user) [PidgeyL]

* Use cpeother if possible. [PidgeyL]

* Add Config.py to cves.py. [PidgeyL]

* Update documentation. [PidgeyL]

* Update documentation. [PidgeyL]

* Merge pull request #29 from PidgeyL/master. [Alexandre Dulaunoy]

  Logging + Bugfix

* Merge pull request #42 from PidgeyL/development. [Pieter-Jan]

  Bugfix + New features

* Bugfix for crash on non-existing cve. [PidgeyL]

* Logging functionallity for the server. [PidgeyL]

* Merge pull request #41 from PidgeyL/development. [Pieter-Jan]

  bugfix: the nltk need a string and not a bytes

* Merge pull request #40 from PidgeyL/development. [Pieter-Jan]

  Documentation

* Merge pull request #28 from PidgeyL/development. [Alexandre Dulaunoy]

  Documentation

* Bugfix: the nltk need a string and not a bytes. [psychedelys]

* Update documentation. [PidgeyL]

* Update documentation. [PidgeyL]

* Initial commit documentation pages - Webcomponent. [PidgeyL]

* Exit on success. [Alexandre Dulaunoy]

* Print help by default if no argument given. [Alexandre Dulaunoy]

* Bug fixed in XML export - CVSS float->string. [Alexandre Dulaunoy]

* Merge pull request #27 from PidgeyL/master. [Alexandre Dulaunoy]

  Graceful shutdown Tornado server

* Merge pull request #39 from PidgeyL/development. [Pieter-Jan]

  fix graceful shutdown for the Tornado server #30

* Fix graceful shutdown for the Tornado server #30. [PidgeyL]

* Merge pull request #26 from PidgeyL/master. [Alexandre Dulaunoy]

  optimization + Security enhancement

* Merge pull request #38 from PidgeyL/development. [Pieter-Jan]

  Security Enhancement

* Upgrade from normal hashing to PBKDF2 #4. [PidgeyL]

* Merge branch 'development' of http://github.com/pidgeyl/cve-search into development. [PidgeyL]

* Merge pull request #37 from PidgeyL/master. [Pieter-Jan]

  make dev branch up to date

* Remove duplicate code. [PidgeyL]

* Bugfix: missing comma. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Merge pull request #25 from PidgeyL/master. [Alexandre Dulaunoy]

  Enhancements

* Removed unused import. [Alexandre Dulaunoy]

* Double import removed. [Alexandre Dulaunoy]

* Unused modules removed. [Alexandre Dulaunoy]

* Remove unused modules. [Alexandre Dulaunoy]

* Bug fixed: runPath undeclared. [Alexandre Dulaunoy]

* Merge pull request #24 from PidgeyL/master. [Alexandre Dulaunoy]

  New Features, Bugfixes, Optimalization

* Merge pull request #23 from PidgeyL/master. [Alexandre Dulaunoy]

  Enhancements + New Features

* Merge pull request #36 from PidgeyL/development. [Pieter-Jan]

  put cve url in config file #6

* Put cve url in config file #6. [PidgeyL]

* Update README.md. [Pieter-Jan]

* Merge pull request #35 from PidgeyL/development. [Pieter-Jan]

  Enhancement + new feature

* Give the option to require no login to access admin panel. [PidgeyL]

* Merge pull request #34 from PidgeyL/development. [Pieter-Jan]

  Development

* Adding salt to the user database #4. [PidgeyL]

* Include menu.html. [PidgeyL]

* Merge pull request #33 from PidgeyL/development. [Pieter-Jan]

  Development

* Taking psychedelys' changes regarding the menu. [psychedelys]

* Taking psychedelys' changes regarding the menu. [psychedelys]

* Actualize psychedelys' commit. [PidgeyL]

* Moved the web menu to an external file to avoid modifying all the files eachtime. [psychedelys]

* Merge pull request #32 from PidgeyL/development. [Pieter-Jan]

  Development

* Implementation SSL for webserver #31. [PidgeyL]

* Adding tornado for asynchronous request handling #13. [PidgeyL]

* Bugfix that causes the config to only read strings. [PidgeyL]

* Merge pull request #29 from PidgeyL/development. [Pieter-Jan]

  Development

* Config class centralizes all the configuration #6. [PidgeyL]

* Beginning of making the config file a separate class #6. [PidgeyL]

* Merge pull request #28 from PidgeyL/development. [Pieter-Jan]

  Development

* Implementation login system on website #4. [PidgeyL]

* Merge branch 'development' of http://github.com/pidgeyl/cve-search into development. [PidgeyL]

* Script to add admins to database #4. [PidgeyL]

* Enhancement for #22: easy copy of cpe by colapsable field. [PidgeyL]

* Config update. [PidgeyL]

* Merge pull request #25 from PidgeyL/development. [Pieter-Jan]

  Enhancement + config update

* Enhancement for #22: easy copy of cpe by colapsable field. [PidgeyL]

* Config update. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #22 from PidgeyL/development. [Alexandre Dulaunoy]

  Bugfixing and Optimization

* Merge pull request #21 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes

* Merge pull request #19 from PidgeyL/development. [Alexandre Dulaunoy]

  enhancements for web view

* Merge pull request #24 from PidgeyL/development. [Pieter-Jan]

  Enhancement + new feature

* Solution for #22: cpe id as tooltip + marking. [PidgeyL]

* Using correct function for previous commit. [PidgeyL]

* Bugfix for previous commit. [PidgeyL]

* Remove duplicate code. [PidgeyL]

* Merge pull request #23 from PidgeyL/development. [Pieter-Jan]

* Merge branch 'development' of http://github.com/pidgeyl/cve-search into development. [PidgeyL]

* Missed variable for setting globalization. [Pieter-Jan]

* Add default cvss score to the config file. [PidgeyL]

* Bugfix that allows to go to negative page numbers with the pager. [PidgeyL]

* Removing abundant function. [PidgeyL]

* Add page length to settings (#6) [PidgeyL]

* Bugfix for the browse per vendor. [PidgeyL]

* Remove debug message. [PidgeyL]

* Merge pull request #18 from PidgeyL/development. [Pieter-Jan]

  Bugfix

* Bugfixing for HTML escaped url's. [PidgeyL]

* Fix variable bug cvedb.vfeed instead of db.vfeed. [PidgeyL]

* Merge pull request #17 from PidgeyL/development. [Pieter-Jan]

* Bugfix for #2, the problem with the %2f being seen as a / [PidgeyL]

* Partial fix for #2: adding/removing cpe's with special chars to lists is now possible. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #17 from PidgeyL/master. [Alexandre Dulaunoy]

  enhancements for web view

* Merge pull request #15 from PidgeyL/master. [Alexandre Dulaunoy]

  fix the query for the blacklist: solves issue #3

* Merge pull request #16 from PidgeyL/development. [Pieter-Jan]

  merged

* Hide rejected cve's with toggle button #9. [PidgeyL]

* Fix missing onLoad() [PidgeyL]

* Clean HTLM head, add new favicon, reintroduce html5shiv #14 (and beginning of #9, by adding the select) [PidgeyL]

* Merge pull request #15 from PidgeyL/development. [Pieter-Jan]

  enhancements for web view

* Fix title from page. [PidgeyL]

* Back to top feature on pages #12. [PidgeyL]

* Collapsable filter with toggle button #11. [PidgeyL]

* Remove abundant code and pages thanks to the filter #10. [PidgeyL]

* Fix the query for the blacklist: solves issue #3. [PidgeyL]

* Merge pull request #13 from xme/master. [Alexandre Dulaunoy]

  Convert float (CVSS) to string before printing

* Convert float (CVSS) to string before printing. [Xavier Mertens]

* Merge pull request #14 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes + finalizing configuration file

* Fix crash on CPE's with more then 4 :'s in string. [PidgeyL]

* Merge branch 'master' of https://github.com/pidgeyl/cve-search. [PidgeyL]

* Fix merge. [PidgeyL]

* Make the mongo database an option in the configurations file. [PidgeyL]

* Fixing bug with runPath. [PidgeyL]

* Allow the change of webserver settings. [PidgeyL]

* Merge pull request #12 from PidgeyL/master. [Alexandre Dulaunoy]

  Enhancements

* Minor bugfix with the year. [PidgeyL]

* Allow users to specify a start year for the CVE's to skip older CVE's, if prefered. [PidgeyL]

* Fix crash when no cve's for a year. [PidgeyL]

* Update copyright. [PidgeyL]

* Remove print from db_cpe_browser testing. [PidgeyL]

* Fix path issues & allow to call scripts from any location (os.path) [PidgeyL]

* Add mongo settings to the config file. [PidgeyL]

* Update depricated pymongo.connection() to pymongo.MongoClient() [PidgeyL]

* Globalize mongo connector settings. [PidgeyL]

* Put all the Redis settings in the config file. [PidgeyL]

* Use update statement for editting CPE's instead of removing and adding. [PidgeyL]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Fix the cancel button. [PidgeyL]

* Merge branch 'master' of http://www.github.com/pidgeyl/cve-search. [PidgeyL]

* Allow editting of cpe's (still a but on cancel button) [PidgeyL]

* Start of configuration file. [PidgeyL]

* Index creation now in the updater. [Alexandre Dulaunoy]

* Merge pull request #11 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes

* Bugfix: NoneType on cpe not matching regex fixed + making the regex match from start to end. [PidgeyL]

* Bugfix: database export not working when file exists. [PidgeyL]

* Bugfix: whitelist exports blacklist file. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Software using cve-search section added. [Alexandre Dulaunoy]

* Handle exception of unavailable redis server. [Alexandre Dulaunoy]

* Merge pull request #10 from PidgeyL/master. [Alexandre Dulaunoy]

  Filter feature

* Bugfix that makes index.py crash when you try to add an entire vendor to a black/- or whitelist. [PidgeyL]

* Update README.md. [Pieter-Jan]

* Updating the Read-Me. [PidgeyL]

* Fix bug where the pager takes the changes in the filterfield. [PidgeyL]

* Bugfixes + multipage navigation. [PidgeyL]

* Make the filter page keep the settings after the search. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge pull request #9 from PidgeyL/master. [Alexandre Dulaunoy]

  fix merge screw-up

* Merge pull request #8 from PidgeyL/master. [Alexandre Dulaunoy]

  fix merge screw-up

* Merge pull request #7 from PidgeyL/master. [Alexandre Dulaunoy]

  Bugfixes, merge and new features

* Removing abundant code + non-working links in pages. [PidgeyL]

* Accept both / and - in dates and added tooltip for userfriendlyness. [PidgeyL]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Fix merge screw-up. [PidgeyL]

* Fix merge screw-up. [PidgeyL]

* Fix merge screw-up. [Pieter-Jan]

* Remove HEAD. [Pieter-Jan]

* Merge with upstream. [PidgeyL]

* Merge pull request #5 from psychedelys/upstream. [Alexandre Dulaunoy]

  standadisation of the shebang

* Added a missing indeg according to updateed docs. [psychedelys]

* Added a link to MyCVE base on whitelist and blacklist, to see the CVE which interessed me. [psychedelys]

* Added the mgmt whitelist and blacklist index. [psychedelys]

* Splitting the cpe search from the original search just to have a cleaner,smaller code. Added the option to search against the cpeother collection. [psychedelys]

* Solving the duplicate on the cpeother. [psychedelys]

* Script to check and ensure that the recommended index are created as recommended. [psychedelys]

* Locating all cpe not found in the official cpe dictionary. [psychedelys]

* Missing an admin link. [psychedelys]

* Closing the zip file. [psychedelys]

* Duplicate keywords. [psychedelys]

* Standadisation of the shebang. [psychedelys]

* Filter function. [PidgeyL]

* Basis filter + small bugfixes. [PidgeyL]

* Visual preparations for the filter. [PidgeyL]

* Make the database store the cvss value in a decimal instead of a string, so filter actions (in the future) will be possible. [PidgeyL]

* URL transformation from get to post + rearrangement breadcrumbs + Regex bugfix + addition of breadcrumbs + fixes breadcrumbs. [PidgeyL]

* Search field filter search. [PidgeyL]

* Basics filter + placeholde in navbar. [PidgeyL]

* Pager tweak: no more next button at the end of the list. [PidgeyL]

* Implement blacklist feature + apply to whitelist. [PidgeyL]

* Bugfix in regex. [PidgeyL]

* Laying basis for filter.html + updating nav bar. [PidgeyL]

* Update navbar. [PidgeyL]

* Bugfix: Pager no longer able to go below 0. [PidgeyL]

* Bugfix: listmanager navigating to versions after adding a product to white-/or blacklist. [PidgeyL]

* Bugfix: load the right scrips.js file in whitelist. [PidgeyL]

* Upgrade from bootstrap 2 to bootstrap 3. [PidgeyL]

* Implementation listmanager (browe through vendors and products to add items to black/- or whitelist with visual navigation) + navigation URL's in the admin panel. [PidgeyL]

* Renaming CPE by product for more uniform format, for later listManagement. [PidgeyL]

* Rearranging code, removing abundant /browse/<vendor>/<product> path, commenting and basis listManagement feature. [PidgeyL]

* Give the pages the right tiles. [PidgeyL]

* Add remove feature to the visual white-/and blacklist lists + bugfix while adding CPE. [PidgeyL]

* Make the blacklist work in the same way as the Whitelist. [PidgeyL]

* Add whitelist view + the posibility to add rules from the web page. [PidgeyL]

* Basic featurs whitelist view (list) [PidgeyL]

* Syntax fix in table from index.html + basis whitelist/blacklist rules. [PidgeyL]

* - Fix invalid path - Fix possible path exploit - add drop and export functions to admin pannel - reformat status. [PidgeyL]

* Add blacklist to the admin pannel + bugfixes. [PidgeyL]

* Fix broken index.py due to changes in db_whitelist.py. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* CPE: references support added. [Alexandre Dulaunoy]

  References href are now added if present in each respective CPE

* CWE from 2.5 to 2.8. [Alexandre Dulaunoy]

* Ensure index on Modified key. [Alexandre Dulaunoy]

  db.cves.ensureIndex( {Modified:1} )

* Remove double requirements (pip3 doesn't like this) [Alexandre Dulaunoy]

* Add blacklist feature. [PidgeyL]

* Put CPEList class in the correct folder. [PidgeyL]

* Create the CPEList class to reduce redundant code in white- and blacklists. [PidgeyL]

* Fix whitelist bug + Fix comments in export + sanitizing input. [PidgeyL]

* Export filename argument as string. [Alexandre Dulaunoy]

* White-list export fixed. [Alexandre Dulaunoy]

* PEP. [Alexandre Dulaunoy]

* -l option added to list existing notifications. [Alexandre Dulaunoy]

* Merge pull request #4 from PidgeyL/master. [Alexandre Dulaunoy]

  Administration page with database update functionality

* Call function to import whitelist instead of os.system() [PidgeyL]

* Exception handling. [PidgeyL]

* Allow comments for whitelisted items. [PidgeyL]

* Changing Modified to Last Major Update for clarity. [PidgeyL]

* Export function for the whitelist. [PidgeyL]

* Make the import selector bash-injection proof. [PidgeyL]

* Whitelist import from admin panel. [PidgeyL]

* Merge remote-tracking branch 'upstream/master' [PidgeyL]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Layouting the web interface. [PidgeyL]

* Basic database update call from web interface. [PidgeyL]

* Verbose mode. [Alexandre Dulaunoy]

* State notification flush option added. [Alexandre Dulaunoy]

* Notification skeleton added. [Alexandre Dulaunoy]

* Notification added. [Alexandre Dulaunoy]

* Removal of notification added (-r) [Alexandre Dulaunoy]

* Verbose mode added (-v) [Alexandre Dulaunoy]

* DB notification tool added. [Alexandre Dulaunoy]

* Merge pull request #3 from PidgeyL/master. [Alexandre Dulaunoy]

  Whitelist feature

* Merge pull request #1 from PidgeyL/admin. [Pieter-Jan]

  introducing admin page

* Introducing admin page. [PidgeyL]

* Introducing admin page. [PidgeyL]

* Copyright references. [PidgeyL]

* Table tweak. [PidgeyL]

* Page navigation through the whitelist. [PidgeyL]

* Allow regex like searches on products. [PidgeyL]

* Whitelist marked item for better visibility. [PidgeyL]

* Remove abundant files. [PidgeyL]

* Add add and remove feature to db_whitelist.py. [PidgeyL]

* Remove abundant files. [PidgeyL]

* Reformatting bootstrap for viewability. [PidgeyL]

* Script for manipulating the whitelist, adding the whitelist link to the pages, implementing the logic in index.py and creating a whitelist class in style.css. [PidgeyL]

* Add the whitelist page. [PidgeyL]

* Basis for the whitelisting view: whitelist management script. [PidgeyL]

* Snort and nmap map added. [Alexandre Dulaunoy]

* Merge pull request #2 from PidgeyL/master. [Alexandre Dulaunoy]

  Formatting + requirements update

* Updating the requirements to run CVE-Search. [PidgeyL]

* Fixing missing " that caused the search function to break. [PidgeyL]

* Updating the dependency (db_mgmt_cpe_dictionary.py) [PidgeyL]

* Rename db_mgmt_cpe_dictionnary.py to db_mgmt_cpe_dictionary.py. [Pieter-Jan]

* Merge branch 'master' of http://github.com/pidgeyl/cve-search. [PidgeyL]

* Fix of the requirements.txt file. [PidgeyL]

* Sorting on Modified instead of last-modified. [PidgeyL]

* Updated requirements.txt for new requirements. [PidgeyL]

* More information on CVE's in Search.html, and changed 'last-modified' with 'published' in index.html and search.html. [PidgeyL]

* Better formatting, by using a function instead of substring, that gives the local time. [PidgeyL]

* Formatting dates to a more userfriendly datetime format. [PidgeyL]

* Add Flask-PyMongo requirement. [Alexandre Dulaunoy]

* Merge pull request #1 from PidgeyL/master. [Alexandre Dulaunoy]

  Web interface update: reverse vulnerable config + search interface

* Reverse sorting order for products from vendors. [PidgeyL]

* Adding a CVE search function to the web pages. [PidgeyL]

* Cleanup and log when the process is waiting. [Alexandre Dulaunoy]

* Remove unused module. [Alexandre Dulaunoy]

* Fixed incorrect keyword used for the getranking method. [Alexandre Dulaunoy]

  Thanks to Didier Stevens and his colleague for the bug report.

* PEP. [Alexandre Dulaunoy]

* Remove unused modules. [Alexandre Dulaunoy]

* Most common terms option (-m) fixed. [Alexandre Dulaunoy]

* Code block of samples added. [Alexandre Dulaunoy]

* Add an advanced usage section. [Alexandre Dulaunoy]

* Output human readable JSON. [Alexandre Dulaunoy]

* Terms are encoded in byte object and it doesn't match a JSON object type. [Alexandre Dulaunoy]

* Bug fix: quit if there is an empty query. [Alexandre Dulaunoy]

* How to install required modules using pip. [Alexandre Dulaunoy]

* PIP requirements.txt file added. [Alexandre Dulaunoy]

  cve-search required packages can be installed via PIP

  sudo pip3 install -r requirements.txt

* Cleanup. [Alexandre Dulaunoy]

* Square Security feed added to add exploit reference. [Alexandre Dulaunoy]

* Square Security feed added to add exploit reference. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Square Security feed added to add exploit reference. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Double import bug fixed and --force option added. [Alexandre Dulaunoy]

  --force option has been added to import again CVE records if the
  initial 2002 CVE exists

* Bug fixed: check correct record for bulk import. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* -c option added to support the CPE redis cache. [Alexandre Dulaunoy]

* CPE browser and search functionality added. [Alexandre Dulaunoy]

* Importing CPE entries in a Redis database to improve lookup. [Alexandre Dulaunoy]

  Until now, this part is only used by the web interface to improve response time

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Clean up: use the library. [Alexandre Dulaunoy]

* Skip parameter added when getting last CVEs. [Alexandre Dulaunoy]

* Pager added while browsing CVEs. [Alexandre Dulaunoy]

* CWE link to MITRE added. [Alexandre Dulaunoy]

* VFeed new mapping added. [Alexandre Dulaunoy]

  map_cve_hp and map_cve_bid added

* Add -n option to index the cpe name. [Alexandre Dulaunoy]

* Bug fix: last-modified is Modified. [Alexandre Dulaunoy]

* Bug fix: last-modified field is "Modified" [Alexandre Dulaunoy]

  When searching the last modified order was not respected and
  the descending option (-l). The mongodb query was using the wrong
  field name.

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Code cleanup - library is now used. [Alexandre Dulaunoy]

* -n (cpe lookup) option adds cpe entries to CSV output. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* CWE collection added. [Alexandre Dulaunoy]

* CWE initial support added. [Alexandre Dulaunoy]

  CWE Weakness import added. This version only imports weaknesses
  and their description. The XML includes much more information
  including a hierarchical structure. More work is required to support
  the whole CWE format.

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Support for NIST NVD vendor statements on CVE added. [Alexandre Dulaunoy]

* -r option only prints entries with ranking available. [Alexandre Dulaunoy]

* Bug fix: skip empty ranking removal if key not presents. [Alexandre Dulaunoy]

* CWE is now imported from the NIST NVD database. [Alexandre Dulaunoy]

* Reference to vfeed @ToolsWatch by default web interface added. [Alexandre Dulaunoy]

  The reference is added from all the keys not part of standard
  NIST or cve-search ranking/entries.

* Vfeed suricata and vmware tables added. [Alexandre Dulaunoy]

  Thanks to @ToolsWatch for the notification.

* Clarification in the installation process. [Alexandre Dulaunoy]

* Library used and vfeed option added. [Alexandre Dulaunoy]

  Dump database in JSON format

  optional arguments:
    -h, --help  show this help message and exit
    -r          Include ranking value
    -v          Include vfeed map

* Dumping ranking is now an option. [Alexandre Dulaunoy]

* Merge pull request #11 from adulau/master. [Wim Remes]

  Ranking and name lookup added in full-text + various fixes including license

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Remove ranking key if there is no ranking value. [Alexandre Dulaunoy]

* Vfeed collection added. [Alexandre Dulaunoy]

* Vfeed added in the db_updater. [Alexandre Dulaunoy]

* Ignore UTF-8 issues while importing vfeed records. [Alexandre Dulaunoy]

* Web.py usage clarified. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Clarify last-modified and add full summary in the tooltip. [Alexandre Dulaunoy]

* Add cpe name|ranking|vfeed lookup in the web interface. [Alexandre Dulaunoy]

  Now the default template is displaying all the know records
  for a CVE including CPE, ranking and vfeed references.

* Return None if CVE requested doesn't exist. [Alexandre Dulaunoy]

* Vfeed dict is not merged when it's a string. [Alexandre Dulaunoy]

* Vfeed lookup added in cves library. [Alexandre Dulaunoy]

  Lookup can be enabled using vfeedlookup=True when instantiating
  the method. The returned value will contain if the vfeed attribute
  if this exists.

* Skip import if vfeed is not modified. [Alexandre Dulaunoy]

* Index to add for the vfeed CVE id collection. [Alexandre Dulaunoy]

* Headers added for db_mgmt_vfeed.py. [Alexandre Dulaunoy]

* Skip vFeed tables where there is no CVE id. [Alexandre Dulaunoy]

  As the CVE id is the main references for cve-search, we discard
  vFeed tables without reference to a CVE id.

* An initial importer for the vFeed database. [Alexandre Dulaunoy]

  The vFeed database is containing the relationship of CVE id
  with various other vulnerability references. The importer is
  adding all the vFeed database into a single collection.

  Thanks to the guys working on vFeed.

* Minimal web interface added to cve-search. [Alexandre Dulaunoy]

  The web interface requires flask (pip install flask). The interface
  is a minimal interface to view the last CVE entries and query
  specific CVE entries. This is the basis for extending cve-search
  in a Web environment.

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Ranking (if present) added in all output. [Alexandre Dulaunoy]

* License properly search.py with a compatible free software license. [Alexandre Dulaunoy]

  To make the licensing consistent within cve-search.

* -r / -n option added (CPE and ranking lookup) [Alexandre Dulaunoy]

* CPE and ranking lookup added in cves.getcve() [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* CPE and ranking lookup displayed while fetching one or more CVE. [Alexandre Dulaunoy]

* Ranking and CPE name lookup added for CPE vendor search. [Alexandre Dulaunoy]

  python3.3 search.py -p joomla: -o json -r -n

  Ranking or product lookup added in the output if option
  -r or -n is used.

* Avoid title output if JSON output is active. [Alexandre Dulaunoy]

* Convert bytes stream into UTF-8 for most frequent terms. [Alexandre Dulaunoy]

* Header for html output for specific CVE-ID search. [Alexandre Dulaunoy]

* Merge branch 'master' of git://github.com/wimremes/cve-search. [Alexandre Dulaunoy]

* Merge pull request #9 from adulau/master. [Wim Remes]

  JSON output fixed for search (fulltext and MongoDB) + a fix in the documentation

* CVE search title in HTML is product search query. [Alexandre Dulaunoy]

* Default output of search is the list of CVE-ID. [Alexandre Dulaunoy]

  If no output format is specified, the default output is the CVE-ID.

* JSON output is fixed. [Alexandre Dulaunoy]

  JSON output is now standard format and using the bson/json conversion.

      You can now use jq to process the results:

  JSON output is fixed

  The BSON format from MongoDB format is now represented following
  the standard JSON representation. Jq can now directly processes
  the results:

      python3.3 search_fulltext.py -q Java | parallel -j 10 python3.3 search.py -r -c | jq '. | {cvss, summary}'

* JSON output is fixed. [Alexandre Dulaunoy]

  JSON output is now standard format and using the bson/json conversion.

  You can now use jq to process the results:

          python3.3 search_fulltext.py -q Java -f | jq '.cvss'

* Documentation added for the keywords visualization. [Alexandre Dulaunoy]

  Clarification on the use of NLTK for stemming the keywords and
  how to use it.

* Merge pull request #8 from adulau/master. [Wim Remes]

  Minor bug fixes, Ranking database and keyword analysis

* Output cveid option added. [Alexandre Dulaunoy]

  -o cveid added to output list of the CVE number of
  the matching search.

* Ranking option added for Atom and RSS feeds. [Alexandre Dulaunoy]

* -j option removed (same as -f) and the cves library is now used. [Alexandre Dulaunoy]

* Avoid MongoDB connection when searches are done in the full-text index. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Lemmatize words but also verbs. [Alexandre Dulaunoy]

* Lemmatization and stopwords added to -s in search_fulltext. [Alexandre Dulaunoy]

  Initially I used a stemming algorithm to filter the variation of words.
  But stemming is not appropriate in this case as the use is not to create
  an index out of the terms but to keep the root of the words. Lemmatization is
  more appropriate in this case.

  The option -s is also checking the stopwords corpus from NTLK to remove
  known stopwords from the result.

* A simple stemming function added to the graph output. [Alexandre Dulaunoy]

* Link to visualization added. [Alexandre Dulaunoy]

* Visualization added in the README. [Alexandre Dulaunoy]

* Export JSON of the term frequency. [Alexandre Dulaunoy]

  Used for the website visualizing the 2000 most used keywords from
  CVE description. http://www.foo.be/cve/

* Dump terms frequency seen in indexed CVEs. [Alexandre Dulaunoy]

  -m <n> dump the <n> most frequent terms
  -l dump the lexicons of all the indexed terms from the CVE description.

* Remove ranking based on cpe regexp. [Alexandre Dulaunoy]

  -d option added to delete the ranking based on their cpe
  name. This can be expressed in any MongoDB regexp.

* Update the db_ranking explanation and display usage. [Alexandre Dulaunoy]

  If the group or the cpe is missing, the usage is now displayed
  with a small explanation of the cve-search ranking.

* Output matching CVE(s) in JSON format. [Alexandre Dulaunoy]

* Method getcve added. [Alexandre Dulaunoy]

* Add a reference to Feedformatter 0.5 required. [Alexandre Dulaunoy]

  Feedformatter is required for dump_last in order to dump in RSS
  or Atom format. The lastest version need to be checkout from:

  http://code.google.com/p/feedformatter/

  Because the pip module is not supporting Python version 3.

* Notes about the values to index in MongoDB. [Alexandre Dulaunoy]

* Python 3 interpreter for the indexing process. [Alexandre Dulaunoy]

* Python 3 is now default for launching updaters. [Alexandre Dulaunoy]

* Merge pull request #7 from adulau/master. [Wim Remes]

  Multiple updates

* -i option added to index new CVE entries. [Alexandre Dulaunoy]

  The db_updater is now calling the indexer to index new entries.

* Add an option to index the last new entries. [Alexandre Dulaunoy]

  You can now index nth newest entries from CVE:

  %python3.3 db_fulltext.py -l 5 -v

* Add an option to index the last new entries. [Alexandre Dulaunoy]

  You can now index nth newest entries from CVE:

  %python3.3 db_fulltext.py -l 5 -v

* Doc-id in schema is now unique. [Alexandre Dulaunoy]

  If you are reindexing from an existing index, you have to
  delete it as the schema changed.

* Update of the index is now supported. [Alexandre Dulaunoy]

  Index presence is checked if it exists. Update document to
  avoid duplicate document in the full-text index. To be used
  for the update process.

* Xmppbot: cvetweet command - output cleaned-up. [Alexandre Dulaunoy]

  First reference is now properly displayed and seperator is
  consistent for all references.

* Add an option to display only ranked CVE. [Alexandre Dulaunoy]

* Added HTML output and optional CPE lookup. [Alexandre Dulaunoy]

  The dump_last command now includes in addition to RSS/Atom
  an HTML output generating a table per CVE entry.

* Clarification of the project + a basic installation guide. [Alexandre Dulaunoy]

* Default byte array is now an unicode string. [Alexandre Dulaunoy]

* Basic XML output added. [Alexandre Dulaunoy]

  -o xml is now working when a product/cpe search is done.

  The output format is a minimal XML format containing each matching
  CVE-ID. The format is including the id, references, date of last
  update and the vulnerable configuration if they are present.

* Remove old README confusing with new README.md. [Alexandre Dulaunoy]

* Dump_last usage added to generate RSS or Atom feeds. [Alexandre Dulaunoy]

* Dump last CVE entries in RSS/Atom format. [Alexandre Dulaunoy]

  Arguments are the following:

  optional arguments:
    -h, --help  show this help message and exit
    -f F        Output format (rss1,rss2,atom)
    -l L        Last n items (default:10)

  requires lib/cves.py

* Minimal library to get last CVE from the database. [Alexandre Dulaunoy]

  You can add the ranking and the CPE lookup for each
  element retrieved from the CVE database by default
  rankinglookup and namelookup are disabled.

  A sample code:

      import cves
      l = cves.last(rankinglookup=True)
      l.get()

* A simple CVE database dumper including ranking in JSON. [Alexandre Dulaunoy]

* Print usage if no arguments are used. [Alexandre Dulaunoy]

* Separate ranking lookup from cpe name lookup. [Alexandre Dulaunoy]

  Now the output can include ranking lookup with or without cpe name.

* Skeleton for the RSS/Atom generator. [Alexandre Dulaunoy]

* Remove limit for search results. [Alexandre Dulaunoy]

* Basic explanation for the fulltext indexing. [Alexandre Dulaunoy]

  db_fulltext.py and search_fulltext.py added in the documentation
  to explain their uses. Be aware that the db_fulltext.py is still
  at the early stage.

* Crude indexer of CVEs to a Whoosh fulltext index. [Alexandre Dulaunoy]

  The fulltext indexer is relying on Whoosh.

  http://packages.python.org/Whoosh/

  The indexing is done by enumerating all items from
  the MongoDB CVE collection and indexing the summary text of each
  CVE. The Path of each document is the CVE-ID.

  The current indexing is indexing all CVEs from the MongoDB. This need
  to be improved when new items are updated (TODO).

  The fulltext indexing is done to overcome the limitation of MongoDB
  regarding fulltext indexing and to improve response time for non-indexed
  records (especially for the XMPP bot).

* Search interface to the fulltext index (in Whoosh) [Alexandre Dulaunoy]

  The search interface to query the Whoosh index to find the matching
  CVEs and output the CVE from the MongoDB collection.

  python3.3 search_fulltext.py -q NFS -q Linux
   -> to query NFS and Linux and output the list of matching CVEs

  python3.3 search_fulltext.py -q NFS -q Linux -j
   -> to query NFS and Linux and output the JSON for each CVE

* -l option added to run the fetcher in a loop. [Alexandre Dulaunoy]

  If you like to run your services in a GNU Screen or a tmux
  session, this allows you to run the updates every hour. without -l
  it's usually for a crontab usage.

* Last-modified check added for CVE and CPE fetch. [Alexandre Dulaunoy]

  CVE and CPE db_mgmt are now checking the last-modified HTTP header
  to skip the download when the file has been already downloaded.
  A new collection has been created to store the meta information
  (like last-modified) about each collection.

  info collection is like this:

  { "_id" : ObjectId("50ba8d5f597549f61b2a25ab"), "db" : "cve",
  "last-modified" : "Sat, 01 Dec 2012 21:01:07 GMT" }
  { "_id" : ObjectId("50ba8dc4597549f61b2a25ac"), "db" : "cpe",
  "last-modified" : "Sat, 01 Dec 2012 05:12:59 GMT" }

  A list of the collections has been added in the README.

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Cvetweet function added in the XMPP bot. [Alexandre Dulaunoy]

  cveweet <last> is outputting a text readable output
  of the last CVE entries with the following format:

  CVE-2011-5058 , The CmbWebserver.dll module of the Control service in 3S CoDeSys 3.4 SP4 Patch 2 allows remote attackers to create arbitrary directories under the web root by specifying a non-existent directory using \ (backslash) characters in an HTTP GET request.http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-336-01A.pdf , http://xforce.iss.net/xforce/xfdb/72339 , http://secunia.com/advisories/47018 , http://aluigi.altervista.org/adv/codesys_1-adv.txt

  CVE-ID, summary, list of references (URLs)

* A small clarification about secondary indexes. [Alexandre Dulaunoy]

* A full-text "search" query added. [Alexandre Dulaunoy]

  search is a full-text search on the summary field of each CVE items.
  You might consider to have an index on the summary field of the cves collection
  , if you expect to have a lot of queries.

  search <keyword(s)>

  You can search for one or more keywords.
  A small help has been also added to the XMPP bot

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* List ranking to be prepared for other formats. [Alexandre Dulaunoy]

* CPE lookup is always done for ranking lookup. [Alexandre Dulaunoy]

* Ranking support added in XMPP bot. [Alexandre Dulaunoy]

  JSON now includes the array ranking (key is ranking).
  If the ranking doesn't exist, the array is empty.

* -l option added to list current rankings. [Alexandre Dulaunoy]

  List all of the rankings in the ranking collection.

* Merge pull request #5 from adulau/master. [Wim Remes]

  A new ranking functionality added and lookup cpe name added for JSON and text output.

* A ranking functionnality added. [Alexandre Dulaunoy]

  Ranking database allows to rank software vulnerabilities based on
  their common platform enumeration name. The ranking can be done
  per organization or department within your organization or any
  meaningful name for you.

  As an example, you can add a partial CPE name like "sap:netweaver"
  which is very critical for your accounting department.

      ./python3.3 db_ranking.py  -c "sap:netweaver" -g "accounting" -r 3

  and then you can lookup the ranking (-r option) for a specific CVE-ID:

      ./python3.3 search.py -c CVE-2012-4341  -r  -n

  The ranking can be extended for notification in the XMPP search bot
  or alike.

  The ranking collection is a new collection in the MongoDB database.

  With the following format (a sample record):

     { "_id" : ObjectId("50b2081e597549f61b2a25a7"), "cpe" : "sap:netweaver", "rank" : [ { "accounting" : 3 } ] }

* Lookup cpe name for text output in product search. [Alexandre Dulaunoy]

* Merge branch 'master' of git://github.com/wimremes/cve-search. [Alexandre Dulaunoy]

* Merge pull request #4 from adulau/master. [Wim Remes]

  Show vendor references only

* Lookup cpe name for JSON output in product search. [Alexandre Dulaunoy]

* Search and show vendor references only in CSV output. [Alexandre Dulaunoy]

  Usually you just want to have the references from the vendor to
  a specific vulnerability and you don't want the full references.

  The -v option allows to search in the hostname of the references
  for a specific vendor. Yep, we assume that a vendor got his own
  domain name (it's usually the case ;-).

    ./search.py -p webex: -o csv  -v "cisco"

  The following example allows you to search webex products and
  show only the vendor links.

* Merge branch 'master' of git://github.com/wimremes/cve-search. [Alexandre Dulaunoy]

* Merge pull request #3 from adulau/master. [Wim Remes]

  Common Platform Enumeration (CPE) added

* URLs fixed. [Alexandre Dulaunoy]

* New README in markdown format. [Alexandre Dulaunoy]

* Search CVE XMPP Bot added. [Alexandre Dulaunoy]

  Simple XMPP bot to query for the last entries in the CVE database
  and to get the output in JSON format. Useful for dynamic application
  requiring a constant feed of updates.

  Current command supported is: last <max>

  To get the n last entries from the CVE database.

  The sleekxmpp library is required.

* Merge branch 'master' of github.com:adulau/cve-search. [Alexandre Dulaunoy]

* Updater script to start db_ scripts and logging. [Alexandre Dulaunoy]

  script that can be used in cron or alike to automatically
  start the db_ updater script and logging the # of updates done.

* -v option added - verbose messages are now optional. [Alexandre Dulaunoy]

  logging is now optional

* -n added to lookup Common Platform Enumeration. [Alexandre Dulaunoy]

  This option replaces cpe name with human-readable description
  of the common platform name. You need to have the cpe collection
  imported via db_mgmt_cpe_dictionnary.py.

  If there is no human-readable description available, the original
  cpe name is used.

  As an example, you can now search with CPE resolution enabled:

  search.py -c CVE-2012-2897 -n

  and without:

  search.py -c CVE-2012-2897

* Importing Common Platform Enumeration into cvedb. [Alexandre Dulaunoy]

  This script is fetching the official Common Platform Enumeration[1]
  into the cve database as a standalone collection. The collection
  format is composed of an id which is the cpe name and the title
  which is the human readable name.

* Merge pull request #2 from adulau/master. [Wim Remes]

  Search a list of CVE-ID

* Search one or more CVE-ID. [Alexandre Dulaunoy]

  like "search.py -c CVE-2012-2897 -c CVE-2012-2553"

* Merge pull request #1 from adulau/master. [Wim Remes]

  set a default CVSS value, option to sort in descending/ascending and case insensitive search

* Fulltext search is now case insensitive. [Alexandre Dulaunoy]

* Option for descending/ascending sort added. [Alexandre Dulaunoy]

* Set a default CVSS value for item without CVSS. [Alexandre Dulaunoy]

* Commented source. [Wim Remes]

* Readme modified. [Wim Remes]

* Search modified. [Wim Remes]

* Initial commit. [Wim Remes]

* Scripts upload. [Wim Remes]

* Test. [Wim Remes]

* Test. [Wim Remes]

* Scripts. [Wim Remes]


