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

Standard Installation
---------------------

Install system requirements:

.. code-block:: bash

    # Install system dependencies by running
    xargs sudo apt-get install -y < requirements.system

Install CVE-Search and its Python dependencies:

.. code-block:: bash

    pip3 install -r requirements.txt

Install MongoDB Community Edition 7.0:

Please check the `mongodb website <https://docs.mongodb.org/manual/installation/>`_ for installation
instructions on different Linux distributions.

The following instructions are for Ubuntu 22.04:

.. code-block:: bash

    # Import the public key used by the package management system
    sudo apt-get install gnupg curl
    curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
        sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg \
            --dearmor

    # Create a list file for MongoDB
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
         sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

    
    # Reload local package database & install the MongoDB package
    sudo apt-get update
    sudo apt-get install -y mongodb-org

    # Run MongoDB
    sudo systemctl daemon-reload
    sudo systemctl start mongod

    # Verify status of mongodb
    sudo systemctl status mongod

    # If all is ok, enable mongodb to start on system startup
    sudo systemctl enable mongod


*This is the end of the standard installation, you may now proceed with :ref:`configuration`*


Production Installation
-----------------------

After the common steps from Standard Installation:

Create a dedicated, unprivileged, user to run the cve-search service

.. code-block:: bash

    sudo adduser cve --home /opt/cve


Create and activate a python virtual environment called *cve-env*

.. code-block:: bash

    sudo su - cve
    
    virtualenv cve-env
    
    source ./cve-env/bin/activate
    

Installation of cve-search in the home directory of the user `cve`

.. code-block:: bash

    cd
    
    git clone https://github.com/cve-search/cve-search.git
    
    cd cve-search
    
    pip3 install -r requirements.txt
    
    exit

    
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
