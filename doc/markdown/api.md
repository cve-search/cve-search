## cve-search HTTP API

The HTTP API outputs JSON. The API accessible if you run at least minimal-web.py.


### Browse vendor and product


To get a JSON with all the vendors:

~~~
curl http://<your local cve-search url>/api/browse
~~~

To get a JSON with all the products associated to a vendor:

~~~
curl http://<your local cve-search url>/api/browse/microsoft
~~~

### Browse CVEs per vendor/product

To get a JSON with all the vulnerabilities per vendor and a specific product:

~~~
curl http://<your local cve-search url>/api/search/microsoft/office
~~~

### Get CVE per CVE-ID

To get a JSON of a specific CVE ID:

~~~
curl http://<your local cve-search url>/api/cve/CVE-2010-3333
~~~

### Get the last updated CVEs

To get a JSON of the last 30 CVEs including CAPEC, CWE and CPE expansions:

~~~
curl http://<your local cve-search url>/api/last
~~~

### Get more information about the current CVE database

To get more information about the current databases in use and when it was updated:

~~~
curl http://<your local cve-search url>/api/dbInfo
~~~



