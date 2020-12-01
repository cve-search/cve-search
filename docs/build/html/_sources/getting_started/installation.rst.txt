.. _intro:

Getting Started
===============

The CVE-Search project is developed for a linux environment and therefore this section describes the installation
procedure for CVE-Search on Linux. Instructions and scripts of this release are written for the current release of Ubuntu LTS on
the x86_64 architecture but will work on most other distributions. In this guide, we assume you are using *apt* as your
package manager. If you are using a different one, install the requirements using your package manager of choice

Before setting up CVE-Search, you have to make sure the all the necessary code is present on your system.
Your best choice is to use *git* to clone CVE-Search from github.

You can clone CVE-Search from

 * git clone https://github.com/cve-search/cve-search.git

Dependencies
------------

.. literalinclude:: ../../../requirements.txt
   :language: bash

.. _installation:

Installation
------------

Install CVE-Search and its python dependencies:

.. code-block:: bash

    pip3 install -r requirements.txt

Install system requirements:

.. code-block:: bash

    # Install system dependencies by running
    xargs sudo apt-get install -y < requirements.system

Install mongodb.

.. code-block:: bash

    wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -

    echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list

    sudo apt-get update

    sudo apt-get install -y mongodb-org

    sudo systemctl daemon-reload

    sudo systemctl start mongod

    # Verify status of mongodb
    sudo systemctl status mongod

    # if all is ok, enable mongodb to start on system startup
    sudo systemctl enable mongod


Please check the `mongodb website <https://docs.mongodb.org/manual/installation/>`_ for installation
instructions on different Linux distributions.

Configuration
-------------
By default CVE-Search takes assumptions on certain configuration aspects of the application. These defaults are noted in
the <<install_dir>>/etc/configuration.ini.sample:

.. literalinclude:: ../../../etc/configuration.ini.sample
    :language: bash

If your setup requires alternate settings and configurations, then copy the etc/configuration.ini.sample to
<<install_dir>>/etc/configuration.ini and adjust accordingly.

Once these steps are completed all the conditions are met for CVE-Search to function properly; continue with
:ref:`populating <pop_db>` the database
