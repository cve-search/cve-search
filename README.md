# cve-search

[![Join the chat at https://gitter.im/cve-search/cve-search](https://badges.gitter.im/cve-search/cve-search.svg)](https://gitter.im/cve-search/cve-search?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
![Build & Test](https://github.com/cve-search/cve-search/workflows/Build%20&%20Test/badge.svg)
![Black formatting](https://github.com/cve-search/cve-search/workflows/Black%20formatting/badge.svg)
![CodeQL](https://github.com/cve-search/cve-search/workflows/CodeQL/badge.svg)

![cve-search logo](https://avatars3.githubusercontent.com/u/15033728?v=3&s=200)

cve-search is a tool to import CVE (Common Vulnerabilities and Exposures) and
CPE (Common Platform Enumeration) into a MongoDB to facilitate search
and processing of CVEs.

The main objective of the software is to avoid doing direct and public lookups
into the public CVE databases. Local lookups are usually faster and you can
limit your sensitive queries via the Internet.

cve-search includes a back-end to store vulnerabilities and related information,
an intuitive web interface for search and managing vulnerabilities,
a series of tools to query the system and a web API interface.

cve-search is used by many organizations including the [public CVE services of CIRCL](https://cvepremium.circl.lu/).

This document gives you basic information how to start with cve-search. For more
information please refer to the documentation in the **_/doc_** folder of this
project.

## Getting started

Check the [documentation](https://cve-search.github.io/cve-search/) to get you started

## Usage

You can search the database using search.py.

```text
usage: search.py [-h] [-q Q] [-p P [P ...]] [--only-if-vulnerable] [--strict_vendor_product] [--lax] [-f F] [-c C] [-o O]
                 [-l] [-n] [-r] [-a] [-v V] [-s S] [-t T] [-i I]

Search for vulnerabilities in the National Vulnerability DB. Data from http://nvd.nist.org.

options:
  -h, --help            show this help message and exit
  -p P [P ...]          P = search one or more products, e.g. o:microsoft:windows_7 or o:cisco:ios:12.1 or
                        o:microsoft:windows_7 o:cisco:ios:12.1. Add --only-if-vulnerable if only vulnerabilities that
                        directly affect the product are wanted.
  --only-if-vulnerable  With this option, "-p" will only return vulnerabilities directly assigned to the product. I.e.
                        it will not consider "windows_7" if it is only mentioned as affected OS in an adobe:reader
                        vulnerability.
  --strict_vendor_product
                        With this option, a strict vendor product search is executed. The values in "-p" should be
                        formatted as vendor:product, e.g. microsoft:windows_7
  --lax                 Strict search for software version is disabled. Likely gives false positives for earlier
                        versions that were not yet vulnerable. Note that version comparison for non-numeric values
                        is done with simplifications.
  -f F                  F = free text search in vulnerability summary
  -c C                  search one or more CVE-ID
  -o O                  O = output format [csv|html|json|xml|cveid]
  -l                    sort in descending mode
  -n                    lookup complete cpe (Common Platform Enumeration) name for vulnerable configuration
  -r                    lookup ranking of vulnerable configuration
  -a                    Lookup CAPEC for related CWE weaknesses
  -v V                  vendor name to lookup in reference URLs
  -s S                  search in summary text
  -t T                  search in last n day (published)
  -T T                  search in last n day (modified)
  -i I                  Limit output to n elements (default: unlimited)
  -q [Q]                Removed. Was used to search pip requirements file for CVEs.
```

Examples:

```bash
./bin/search.py -p cisco:ios:12.4
./bin/search.py -p cisco:ios:12.4 -o json
./bin/search.py -f nagios -n
./bin/search.py -p microsoft:windows_7 -o html
```

If you want to search all the WebEx vulnerabilities and only printing the official references from the supplier.

```bash
./bin/search.py -p webex: -o csv  -v "cisco"
```

You can also dump the JSON for a specific CVE ID.

```bash
./bin/search.py -c CVE-2010-3333 -o json
```

Or dump the last 2 CVE entries in RSS or Atom format.

```bash
./bin/dump_last.py -f atom -l 2
```

Or you can use the webinterface.

```bash
./web/index.py
```

## Usage of the ranking database

There is a ranking database allowing to rank software vulnerabilities based on
their common platform enumeration name. The ranking can be done per organization
or department within your organization or any meaningful name for you.

As an example, you can add a partial CPE name like "sap:netweaver" which is very
critical for your accounting department.

```bash
./sbin/db_ranking.py  -c "sap:netweaver" -g "accounting" -r 3
```

and then you can lookup the ranking (-r option) for a specific CVE-ID:

```bash
./bin/search.py -c CVE-2012-4341  -r  -n
```

## Advanced usage

As cve-search is based on a set of tools, it can be used and combined with standard Unix tools. If you ever wonder what are the top vendors using the term "unknown" for their vulnerabilities:

```bash
python3 bin/search_fulltext.py -q unknown -f \
    | jq -c '. | .vulnerable_configuration[0]' \
    | cut -f5 -d: | sort  | uniq -c  | sort -nr | head -10

1500 oracle
381 sun
372 hp
232 google
208 ibm
126 mozilla
103 microsoft
100 adobe
 78 apple
 68 linux
 ```

You can compare CVSS (Common Vulnerability Scoring System ) values of some products based on their CPE name. Like comparing oracle:java versus sun:jre and using R to make some statistics about their CVSS values:

```bash
python3 bin/search.py -p oracle:java -o json \
  | jq -r '.cvss' | Rscript -e 'summary(as.numeric(read.table(file("stdin"))[,1]))'

Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
1.800   5.350   9.300   7.832  10.000  10.000
```

```bash
python3 bin/search.py -p sun:jre -o json \
  | jq -r '.cvss' | Rscript -e 'summary(as.numeric(read.table(file("stdin"))[,1]))'

Min. 1st Qu.  Median    Mean 3rd Qu.    Max.
0.000   5.000   7.500   7.333  10.000  10.000
```

## Fulltext indexing

If you want to index all the CVEs from your current MongoDB collection:

```bash
./sbin/db_fulltext.py -l 0
```

and you query the fulltext index (to get a list of matching CVE-ID):

```bash
./bin/search_fulltext.py -q NFS -q Linux
```

or to query the fulltext index and output the JSON object for each CVE-ID:

```bash
./bin/search_fulltext.py -q NFS -q Linux -f
```

## Fulltext visualization

The fulltext indexer visualization is using the fulltext indexes to build
a list of the most common keywords used in CVE. [NLTK](http://nltk.org/) is
required to generate the keywords with the most common English
stopwords and lemmatize the output. [NTLK for Python 3](http://nltk.org/nltk3-alpha/)
exists but you need to use the alpha version of NLTK.

```bash
./bin/search_fulltext.py  -g -s >cve.json
```

![cve-search visualization](https://farm9.staticflickr.com/8109/8603509755_c7690c2de4_n.jpg "CVE Keywords Visualization Using Data From cve-search")

You can see a visualization on the [demo site](http://www.foo.be/cve/).

## Web interface

The web interface is a minimal interface to see the last CVE entries and
query a specific CVE. You'll need flask in order to run the website and
[Flask-PyMongo](http://flask-pymongo.readthedocs.org/en/latest/). To start
the web interface:

```bash
cd ./web
./index.py
```

Then you can connect on `http://127.0.0.1:5000/` to browser the last CVE.

## Web API interface

The web interface includes a minimal JSON API to get CVE by ID, by vendor or product.
A public version of the API is also accessible on [cve.circl.lu](https://cve.circl.lu/).

List the know vendors in JSON

```bash
curl "http://127.0.0.1:5000/api/browse/"
```

Dump the product of a specific vendor in JSON

```jq
curl "http://127.0.0.1:5000/api/browse/zyxel"
{
  "product": [
    "n300_netusb_nbg-419n",
    "n300_netusb_nbg-419n_firmware",
    "p-660h-61",
    "p-660h-63",
    "p-660h-67",
    "p-660h-d1",
    "p-660h-d3",
    "p-660h-t1",
    "p-660h-t3",
    "p-660hw",
    "p-660hw_d1",
    "p-660hw_d3",
    "p-660hw_t3"
  ],
  "vendor": "zyxel"
}
```

Find the associated vulnerabilities to a vendor and a product.

```jq
curl "http://127.0.0.1:5000/api/search/zyxel/p-660hw" | jq .
[
  {
    "cwe": "CWE-352",
    "references": [
      "http://www.exploit-db.com/exploits/33518",
      "http://secunia.com/advisories/58513",
      "http://packetstormsecurity.com/files/126812/Zyxel-P-660HW-T1-Cross-Site-Request-Forgery.html",
      "http://osvdb.org/show/osvdb/107449"
    ],
    "vulnerable_configuration": [
      "cpe:/h:zyxel:p-660hw:_t1:v3"
    ],
    "Published": "2014-06-16T14:55:09.713-04:00",
    "id": "CVE-2014-4162",
    "Modified": "2014-07-17T01:07:29.683-04:00",
    "cvss": 6.8,
    "summary": "Multiple cross-site request forgery (CSRF) vulnerabilities in the Zyxel P-660HW-T1 (v3) wireless router allow remote attackers to hijack the authentication of administrators for requests that change the (1) wifi password or (2) SSID via a request to Forms/WLAN_General_1."
  },
  {
    "cwe": "CWE-20",
    "references": [
      "http://www.kb.cert.org/vuls/id/893726"
    ],
    "vulnerable_configuration": [
      "cpe:/h:zyxel:p-660h-63:-",
      "cpe:/h:zyxel:p-660h-t1:-",
      "cpe:/h:zyxel:p-660h-d3:-",
      "cpe:/h:zyxel:p-660h-t3:v2",
      "cpe:/h:zyxel:p-660h-t1:v2",
      "cpe:/h:zyxel:p-660h-d1:-",
      "cpe:/h:zyxel:p-660h-67:-",
      "cpe:/h:zyxel:p-660h-61:-",
      "cpe:/h:zyxel:p-660hw_t3:v2",
      "cpe:/h:zyxel:p-660hw_t3:-",
      "cpe:/h:zyxel:p-660hw_d3:-",
      "cpe:/h:zyxel:p-660hw_d1:v2",
      "cpe:/h:zyxel:p-660hw_d1:-",
      "cpe:/h:zyxel:p-660hw:_t1:v2",
      "cpe:/h:zyxel:p-660hw:_t1:-"
    ],
````

## Software using cve-search

* [MISP modules](http://misp.github.io/misp-modules/expansion/#cve) cve-search to interact with MISP
* [MISP module cve-advanced](https://github.com/MISP/misp-modules/blob/master/misp_modules/modules/expansion/cve_advanced.py) to import complete CVE as MISP objects
* [cve-portal](https://www.github.com/CIRCL/cve-portal) which is a CVE notification portal
* [cve-search-mt](https://www.github.com/NorthernSec/cve-search-mt) which is a set of management tools for CVE-Search
* [cve-scan](https://www.github.com/NorthernSec/cve-scan) which is a NMap CVE system scanner
* [Mercator](https://www.github.com/dbarzin/mercator) which is an application that allow the mapping of an information system

## Docker versions

Official dockerized version of cve-search:

[CVE-Search-Docker](https://github.com/cve-search/CVE-Search-Docker)

There are some unofficial dockerized versions of cve-search (which are not maintained by us):

* [docker-cve-search](https://github.com/ttimasdf/docker-cve-search)
* [cve-search-docker](https://github.com/leojcollard/cve-search-docker)

## Changelog

You can find the changelog on [GitHub Releases](https://github.com/cve-search/cve-search/releases)
([legacy changelog](https://www.cve-search.org/Changelog.txt)).

## License

cve-search is free software released under the "GNU Affero General Public License v3.0"

```text
Copyright (c) 2012 Wim Remes - https://github.com/wimremes/
Copyright (c) 2012-2024 Alexandre Dulaunoy - https://github.com/adulau/
Copyright (c) 2015-2019 Pieter-Jan Moreels - https://github.com/pidgeyl/
Copyright (c) 2020-2024 Paul Tikken - https://github.com/P-T-I
```
