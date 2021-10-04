from lib.DatabasePlugins import *

_local_vars = locals()


class DatabasePluginNotFound(Exception):
    pass


class DatabasePluginLoader(object):
    def __init__(self):

        mods = [
            {plugin: _local_vars[plugin]}
            for plugin in _local_vars
            if not plugin.startswith("_")
            and not plugin.startswith("DatabasePluginLoader")
            and not plugin.startswith("DatabasePluginNotFound")
        ]

        plugins = {}

        for each in mods:
            for key, val in each.items():
                plugin_class = [plug for plug in dir(val) if plug.endswith("Plugin")]
                plugins[key] = getattr(val, plugin_class[0])

        self.database_choises = dict(plugins)

    def load_plugin(self, name):
        """
        Method to load the requested plugin

        :param name: Name of the database plugin to load
        :type name: str
        :return: Plugin class
        :rtype: class
        """
        try:
            plugin = self.database_choises[name]
            return plugin
        except KeyError:
            raise DatabasePluginNotFound("Cannot find the requested plugin!")
