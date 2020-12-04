.. _web:

Webgui
======

This document will explain how to set up the web-component for CVE-Search.
This documentation assumes you have installed all the components of CVE-Search and ran the first initialization scripts.

Settings
########

Before we start the web server, we will go over the settings in the configuration.ini file, and explain what every
setting means. The settings for the web-server can be found under the head [Webserver]

+---------------+-----------------------+-----------------------------------------------------------+
| Setting       | Default setting       | Explanation                                               |
+===============+=======================+===========================================================+
| Host          | 127.0.0.1             | | The address by which the web-server is accessible.      |
|               |                       | | Either loop-back or one of the machine's IP addresses   |
+---------------+-----------------------+-----------------------------------------------------------+
| Port          | 5000                  |  The port on which the web-server will be running         |
+---------------+-----------------------+-----------------------------------------------------------+
| Debug         | True                  | | When the server runs in [debug mode](#debug), SSL will  |
|               |                       | | be turned off and the web-server will be in             |
|               |                       | | *Blocking Mode*                                         |
+---------------+-----------------------+-----------------------------------------------------------+
| PageLength    | 50                    | The amount of CVEs that will be displayed per page        |
+---------------+-----------------------+-----------------------------------------------------------+
| LoginRequired | False                 | | Decides whether [users](#users) have to log in to       |
|               |                       | | access [admin pages](#admin).                           |
+---------------+-----------------------+-----------------------------------------------------------+
| SSL           | False                 | | Decides whether SSL is used to secure the connection.   |
|               |                       | | See [SSL](#ssl) for more information on how to set      |
|               |                       | | this up                                                 |
+---------------+-----------------------+-----------------------------------------------------------+
| Certificate   | ssl/cve-search.crt    | | The certificate used for the SSL connection. More info  |
|               |                       | | under [SSL](#ssl)                                       |
+---------------+-----------------------+-----------------------------------------------------------+
| Key           | ssl/cve-search.key    | | The key used for the SSL connection.                    |
|               |                       | | More info under [SSL](#ssl)                             |
+---------------+-----------------------+-----------------------------------------------------------+
| WebInterface  | Full                  | Whether the webgui should start in full mode or minimal   |
+---------------+-----------------------+-----------------------------------------------------------+

Debug mode
##########

Running the server in debug mode allows for easier development of the server. By setting this value on *True*, the
server will only use the Flask module. This means that the server will be set to *Blocking Mode*, SSL will
be disabled, overriding the configuration.ini settings, and the server will give more visual debug output.

Setting this value on *False*, the server will take the default SSL settings from the configuration.ini file and will
enable the Gevent module, putting the server in *Non-Blocking mode*, and reduce the visual debug output.

It is advised not to run the server in debug mode when you run it in a production environment. However, when you are
developing or testing CVE-Search alone or with a small group of people, it is advised to run it in debug mode, as it
will give you a lot more information when the application crashes for some reason.

Users and Login
###############

If you decide to make use of CVE-Search's login system, you will need to add users to the user-list. To do this,
you'll be using the *db_mgmt_admin.py* script.

This script takes several parameters, as mentioned below:

+------------+--------------+-----------------------------------------------+
| Parameter  | Arguments    | Explanation                                   |
+============+==============+===============================================+
| -h, --help | None         | Displays the help page                        |
+------------+--------------+-----------------------------------------------+
| -a A       | name of user | Add a user account                            |
+------------+--------------+-----------------------------------------------+
| -c C       | name of user | Change the password of a user                 |
+------------+--------------+-----------------------------------------------+
| -r R       | name of user | Remove a user account                         |
+------------+--------------+-----------------------------------------------+
| -p P       | name of user | Promote a user account to Master              |
+------------+--------------+-----------------------------------------------+
| -d D       | name of user | Demote a user account to a normal user        |
+------------+--------------+-----------------------------------------------+

Master accounts
###############

The first account that you add will automatically be a Master account. Master accounts are accounts with the privilege
to add, remove, promote and demote other user accounts. Every user can access the admin panel, regardless whether he
has a Master account or not.

Creating accounts
#################

You can create a user account by using the command `Python3 db_mgmt_admin.py -a user`, where user is the name of your
account.

If this is the first account in the database, the script will not require a Master password, and the account
created will be a Master account. If this is not the first account, the script will ask you to log in using a Master
account, before you can proceed. Next, the script will ask you for a new password for the user. You will not see the
characters when you type the password. This is to protect the user's password from spying eyes. After verifying the
password, the user account will be created.

Changing account passwords
##########################

Every user can change his or her password by typing `Python3 db_mgmt_admin.py -c user`, where user is the name of your
account.

Running this script will ask you the current password of your user account. After entering this password, it will ask
you to type your new password twice. After you typed your new password, the user will be updated, and the new password
will be stored.

Removing accounts
#################

Master accounts can remove users by typing `Python3 db_mgmt_admin.py -r user`, where user is the name of the account.

Removing an account requires a Master account to log in. If the account you're trying to remove is not the last Master
account, it will not be removed.

Promoting accounts
##################

Master accounts can promote other accounts by typing *Python3 db_mgmt_admin.py -p user*, where user is the name of
the account.

Promoting a user grants this user the privileges to add, remove, promote and demote other users.

Demoting accounts
#################

Master accounts can demote him/herself or other accounts by typing `Python3 db_mgmt_admin.py -d user`, where user is
the name of the account.

If the account you're trying to demote is the last Master account, it won't work. Demoting users reduces their
privileges to that of a normal user, so he/she can only change his or her own password.

SSL - Secure Socket Layer
#########################

The use of SSL will make sure your users traffic can not be sniffed. This will make sure people with bad intentions
can't get user passwords or any other information.

Setting up SSL
--------------

To set up SSL on your server, you need a certificate and a key. On Linux, you can create these by running the
following command:

.. code-block:: bash

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /ssl/cve-search.key -out /ssl/cve-search.crt


The parameter `-days` lets you choose the duration the certificate must be valid. In this example, this is 365 days.

The parameter `-newkey` lets you choose the algorithm and length of the key and certificate. If you don't know what
you're doing, use the default value.

The parameter `-keyout` is the output of your new SSL key. Make sure this location is the same as the *Key value of your
configuration.ini file.

The parameter `-out` is the output for your new SSL certificate. Make sure this location is the same as the
*Certificate* value of your configuration.ini file.


After hitting the Enter key, you'll be requested to fill out your organizational information. This will be visible on
the certificate, and will be a way for your users to verify your certificate, as this will be *self-signed*.
When users surf to your website, they will get a warning, and they will have to accept this certificate.

Starting and stopping the web-server
####################################

Once you set up the configurations.ini file how you want it to be, you can start the webserver by simply
running `python3 web/index.py`. To stop the server, you can simply press the **CTRL+C** combination.


Alternatively, on Linux, you can start the server by running `nohup python3 web/index.py &`. This will make the server
run in the background. However, this makes it so you cannot use the **CTRL+C** combination. Instead, you will have to
find the processes related to the web-server, by using `ps aux | grep web/index.py`. Then kill them using the
`kill -15` command on all the processes related to the server.

Using the web-server
####################

Pages for normal users
----------------------

All users will be able to view the recent CVE's, search for CVEs related to a product and get all CVE information. In
the table below, you can find a short description of each page this user can go to.

+-------------------+---------------------------------------------------------------------------+
| Page              | Description                                                               |
+===================+===========================================================================+
| Recent            | | An overview of all the CVE's, ordered from recent to old. You can use   |
|                   | | the filter to enhance your search.                                      |
+-------------------+---------------------------------------------------------------------------+
| CVE               | | The overview of a CVE. You can find all the information that is in the  |
|                   | | CVE-Search database in here.                                            |
+-------------------+---------------------------------------------------------------------------+
| Browse per vendor | | Lets you search CVEs per product. The result is ordered from new to old,|
|                   | | sorted by Last Major Update                                             |
+-------------------+---------------------------------------------------------------------------+

Every CVE has a few base fields. These fields are:

+---------------------------+-------------------------------------------------------------------+
| Field                     | Explanation                                                       |
+===========================+===================================================================+
| ID                        | The identifier of a CVE                                           |
+---------------------------+-------------------------------------------------------------------+
| Summary                   | | The description of a CVE, with an explanation the attack vector |
|                           | | and the result                                                  |
+---------------------------+-------------------------------------------------------------------+
| References                | | Links to other websites with information about the CVE. These   |
|                           | | can be vendor statements, explanations, etc                     |
+---------------------------+-------------------------------------------------------------------+
| Vulnerable Configuration  | | The products that are vulnerable to the CVE. This field can be  |
|                           | | empty if the CVEis still new, and information is not complete   |
|                           | | yet.                                                            |
+---------------------------+-------------------------------------------------------------------+
| CVSS                      | | The score given to a CVE. This score represents the risk and    |
|                           | | damage. If this field is not yet set by NIST's NVD, the default |
|                           | | value, specified in the configuration.ini file,will be used.    |
+---------------------------+-------------------------------------------------------------------+
| Last Major Update         | | The last major update a CVE had. This is set to the latest      |
|                           | | update where information is added or changed                    |
+---------------------------+-------------------------------------------------------------------+
| Published                 | The date the CVE got published                                    |
+---------------------------+-------------------------------------------------------------------+
| Last Modified             | | The date the CVE got last modified. Modifications can be        |
|                           | | spelling changes, changes in wording etc.                       |
+---------------------------+-------------------------------------------------------------------+

Admin Pages
-----------

When login is required, admins have access to more pages then normal users. If login is not required, normal users
will have access to these pages as well.

The admin page is the main control panel for the admin. From this page, he can update the database, as well as view
and manage the white/and blacklist. All the admin functions are accessible by using the navigation buttons.

Updating the database
---------------------

Updating the database can be done by a press of the update button, on the admin panel. Alternatively, you can use
the update script `db_updater.py`. The button press runs `python3 db_updater.py -civ`. For more information on the
scripts parameters, run `Python3 db_updater -h`.

The sources used by CVE-Search are listed in the configuration.ini file.

Managing white- and blacklists
------------------------------

The white- and blacklists can be used to manage the information your users see. Adding a CPE to the whitelist, any
CVE which has this CPE in its vulnerable configurations will be marked. Adding a CPE to the blacklist will hide all
the CVEs which are only applicable to this CPE. This way you can hide CVEs for products you're not interested in.

This default behavior can be overruled by the search filter on the "Recent" page, and by no means excludes these items
from the database.

CPE's have a specific format, and can be used as regular expression to mark or exclude CPE's. The default format of a
CPE is: *cpe:/type:vendor:product:version*

The type can be **a** for application, **h** for hardware or **o** for operating system.


**Example:**

*cpe:/h:3com:3c13612:5.26.2* is a piece of hardware, produced by 3com. The product name is 3c13612, and the version
is 5.26.2. Adding this to the whitelist will make CVE-Search mark all the CVEs applicable to this specific setup.

However, if you don't want just this version number, you could add *cpe:/h:3com:3c13612:*, for all the versions,
or even *cpe:/h:3com:* for all the hardware 3com produces.

Logging
#######

Logging can be useful when multiple people are using your server, and you cannot monitor it the entire time.
When your server does not run in debug mode, you can use logging to still get reports of crashes or malfunctions.

The configurations.ini file contains a few options regarding logging, which are briefly explained below:

+-----------+-----------------------+-----------------------------------------------------------+
| Setting   | Default setting       | Explanation                                               |
+===========+=======================+===========================================================+
| Logfile   | log/cve-search.log    | The file the logs will be saved to                        |
+-----------+-----------------------+-----------------------------------------------------------+
| MaxSize   | 100MB                 | | Maximum size of the logfile. Can take the format        |
|           |                       | | of `100`, `100 b` or `100b`. b means bytes, mb means    |
|           |                       | | megabytes and gb means gigabytes.                       |
+-----------+-----------------------+-----------------------------------------------------------+
| Backlog   | 5                     | Amount of logfiles the server saves.                      |
+-----------+-----------------------+-----------------------------------------------------------+

When the size of the logfile exceeds the amount set in MaxSize, a new file will be created. If the settings are like
above, this file will be called log/cve-search.1.log. If either MaxSize or Backlog is set to 0, this will not happen,
and the logfile will have no maximum size.
