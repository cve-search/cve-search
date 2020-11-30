from abc import ABC, abstractmethod


class DatabasePluginBase(ABC):
    """
    The DatabasePluginBase is the base class of all database backend plugins supported by cve search. The default
    backend plugin is mongodb. If you wish to use a different backend you could provide your own plugin. Plugins should
    be placed within the lib.DatabasePlugins folder. Plugins should be a class derived from this class and the class
    name should end with 'Plugin' for it to be automatically picked up by the DatabasePluginLoader and presented to cve
    search. The name of the plugin should be defined in the 'PluginName' variable of the configuration.ini file and
    should be the same as the name of the file (minus the '.py') in which the plugin class resides.

    ******************************************************************************************************************
            FOR Now only a small part of the API makes use of this plugin based database access all other
                            endpoints and functionalities do not use these plugins yet
    ******************************************************************************************************************
    """

    def __init__(self):
        pass

    @abstractmethod
    def query_docs(self, **kwargs):
        """
        Method used to perform a extended query against the database in order to fetch data.

        This method should accept:

        :param retrieve: Collection/table name where to retrieve the documents from
        :type retrieve: str
        :param dict_filter: A column filter based on a python dictionary
        :type dict_filter: dict
        :param sort: Field to sort on or list of tuples of field and direction; e.g. (for mongodb)
                    [("field", pymongo.DESCENDING), ("field2", pymongo.ASCENDING)]
        :type sort: str or list
        :param limit: Can be used to limit the amount of returned results
        :type limit: int
        :param skip: Can be used to skip the first x records of the returned results
        :type skip: int
        :param query_filter: Python Dictionary to include fields to return in the query results
                             (e.g.: {field1: 1, field2: 1})
        :type query_filter: dict
        :param sort_dir: A general sorting direction; e.g. DESC for DESCENDING, ASC for ASCENDING
        :type sort_dir: str

        This method should return:

        :return: A list of dictionaries whith the data saved in the backend. Each dictionary represents a single
                 row/document and the dictionary keys represent the fields/columns in the row/document
        :rtype: list

        """
        raise NotImplementedError

    @abstractmethod
    def fetch_one(self, **kwargs):
        """
        The fetch one method returns a single record based on the provided parameters.

        This method should accept:

        :param retrieve: Collection name where to retrieve the documents from
        :type retrieve: str
        :param dict_filter: A column filter based on a python dictionary
        :type dict_filter: dict
        :param query_filter: Dict with fields to exclude or include; e.g. {"hosts": 0} or {"hosts": 1}
        :type query_filter: dict

        This method should return:

        :return: Dictionary with items from database or None
        :rtype: dict or None
        """
        raise NotImplementedError

    @abstractmethod
    def create_schema(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def count(self, **kwargs):
        """
        Method for retrieving a document count

        This method should accept:

        :param retrieve: Collection/table to retrieve the count from
        :type retrieve: str
        :param dict_filter: A column filter based on a python dictionary
        :type dict_filter: dict

        This method should return:

        :return: Count
        :rtype: int
        """
        raise NotImplementedError

    @abstractmethod
    def datatables_data_columns_ordering(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def datatables_data_filter(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def datatables_data_order(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def addUser(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def changePassword(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def verifyUser(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def deleteUser(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def setAdmin(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def setLocalOnly(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def isMasterAccount(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def userExists(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def isSingleMaster(self, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def getUser(self, **kwargs):
        raise NotImplementedError