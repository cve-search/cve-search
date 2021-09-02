.. _webplugins:

Webgui Plugins
==============

Cve-Search has build in support for (custom) plugin development. Cve-Search uses in turn a Flask plugin called
"Flask-Plugins" to facilitate the custom creation of plugins. Several events have been build into the templates of
Cve-Search where custom plugins can listen for and attach content if needed. For a more detailed explanation of the
possibilities of the Flask-Plugins library please consult
`the documentation <https://flask-plugins.readthedocs.io/en/master/>`_.

General remarks
###############

At this moment there are no 'out of the box' (besides a 'hello world' plugin) plugins that can be used; the old
plugin repository (`<https://github.com/cve-search/Plugins>`_) is no longer maintained and plugins described /
posted there will no longer work with the current version of Cve-Search. Newly developed plugins can be forwarded to the
Cve-Search codebase via a PR; we will make them part of the main code-base of Cve-Search and no longer reside to a
separate repository.

Plugin location
###############

The Flask-Plugins documentation described how a plugin needs to be structured (basically it follows the guidelines for a
flask application); and once that is done, plugins should be stored in the web/plugins folder and after the webserver is
restarted it will be visible to Cve-Search.

In the admin section of Cve-Search (/admin) a new widget is created where all the discovered plugins are displayed. Within
that widget plugins can be enabled or disabled.

**Bear in mind that every action (enable/disable/adding or removing new plugin) will need a restart of the webserver**

Supported events
################

Currently Cve-Search supports 4 different type of events (more like locations where plugins can 'hook' into):

- tmpl_navigation_last;
- tmpl_navigation_dropdown;
- footer_tab_header;
- footer_tab_content.

The names of the events should be pretty self-explanatory as to where they are mapped in the webinterface.
