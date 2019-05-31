FROM python:3
MAINTAINER cstoolio@koderman.de

# copy requirements first - if unchanged, docker will skip "pip install"!
COPY requirements.txt /
RUN pip install -r /requirements.txt

# now copy application:
COPY . /cve-search
CMD bash


# run this container with bash first to
# populate database and execute searches from bash

# fastest init:
#CMD db.cves.drop()
#CMD sbin/db_mgmt_create_index.py
#CMD python /cve-search/sbin/db_mgmt_cpe_dictionary.py
#CMD python /cve-search/sbin/db_mgmt.py -p

# populate database for very first time:
#CMD python /cve-search/sbin/db_mgmt.py -p
#CMD python /cve-search/sbin/db_mgmt_cpe_dictionary.py
#CMD python /cve-search/sbin/db_updater.py -c

# update the database:
#CMD python /cve-search/sbin/db_updater.py -v

# if necessary at some point: drop and re-populate database:
#CMD python /cve-search/sbin/db_updater.py -v -f

# minimal import - runs indexer:
#CMD python /cve-search/sbin/db_updater.py -m


