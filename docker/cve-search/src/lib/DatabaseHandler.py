from lib.ApiRequests import JSONApiRequest
from lib.Config import Configuration
from lib.DatabasePluginBase import DatabasePluginBase
from lib.DatabasePlugins.config import DatabasePluginLoader


class DatabaseHandler(object):
    def __init__(self):
        self.config = Configuration()
        database_plugin = self.config.readSetting("Database", "PluginName", self.config.default["DatabasePluginName"])

        self.dbpluginloader = DatabasePluginLoader()

        fetched_plugin = self.dbpluginloader.load_plugin(database_plugin)()

        if isinstance(fetched_plugin, DatabasePluginBase):
            self.connection = fetched_plugin
        else:
            raise TypeError("The provided plugin is not derived from the DatabasePluginBase class!")

    def handle_api_json_query(self, request):
        if not isinstance(request, JSONApiRequest):
            raise TypeError(
                "Wrong type received, expected JSONApiRequest but got: {}".format(
                    type(request)
                )
            )

        results = request.process(self.connection)

        return results
