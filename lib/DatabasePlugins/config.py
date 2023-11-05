import glob
import importlib
from os.path import dirname, basename, isfile, join

modules = glob.glob(join(dirname(__file__), "*.py"))
all_plugins = [
    basename(f)[:-3]
    for f in modules
    if isfile(f) and not f.endswith("__init__.py") and not f.endswith("config.py")
]


class DatabasePluginNotFound(Exception):
    pass


class DatabasePluginLoader(object):
    def __init__(self):
        mods = [
            {plugin: importlib.import_module(f"lib.DatabasePlugins.{plugin}")}
            for plugin in all_plugins
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
