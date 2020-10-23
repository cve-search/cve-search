import re
import sre_constants
import urllib
from collections import defaultdict

import bson
import pymongo
from pymongo import DESCENDING, ASCENDING
from pymongo.collection import Collection
from werkzeug.security import generate_password_hash, check_password_hash

from lib.DatabaseLayer import sanitize
from lib.DatabasePluginBase import DatabasePluginBase
from lib.Config import Configuration

config = Configuration()


HOST = config.readSetting("Database", "Host", config.default["mongoHost"])
PORT = config.readSetting("Database", "Port", config.default["mongoPort"])
DATABASE = config.getMongoDB()
USERNAME = urllib.parse.quote(
    config.readSetting("Database", "Username", config.default["mongoUsername"])
)
PASSWORD = urllib.parse.quote(
    config.readSetting("Database", "Password", config.default["mongoPassword"])
)


class MongoPlugin(DatabasePluginBase):
    def __init__(self):
        """
        Custom MongoDBPlugin
        """
        super().__init__()

        if USERNAME and PASSWORD:
            mongoURI = "mongodb://{username}:{password}@{host}:{port}/{db}".format(
                username=USERNAME, password=PASSWORD, host=HOST, port=PORT, db=DATABASE,
            )
        else:
            mongoURI = "mongodb://{host}:{port}/{db}".format(
                host=HOST, port=PORT, db=DATABASE
            )

        connect = pymongo.MongoClient(mongoURI, connect=False)
        self.connection = connect[DATABASE]

        self.user_store = connect[DATABASE]["mgmt_users"]

        for each in self.connection.list_collection_names():
            setattr(
                self,
                "store_{}".format(each),
                Collection(database=self.connection, name=each),
            )

    def create_schema(self, **kwargs):
        pass

    def count(self, retrieve, dict_filter={}):
        """
        Method for retrieving a document count

        :param retrieve: Collection to retrieve the count from
        :type retrieve: str
        :param dict_filter: dict representing a filter see pyMongo doc
        :type dict_filter: dict
        :return: Count
        :rtype: int
        """
        if isinstance(dict_filter, dict):
            return getattr(self, "store_{}".format(retrieve)).count_documents(filter=dict_filter)
        else:
            return getattr(self, "store_{}".format(retrieve)).count_documents(filter={"$and": dict_filter})

    def query_docs(
        self,
        retrieve=None,
        dict_filter={},
        sort=None,
        limit=None,
        skip=0,
        query_filter=None,
        sort_dir="DESC",
        id_to_string=True,
    ):
        """
        Method used to perform a extended query against the database in order to fetch documents.

        :param retrieve: Collection name where to retrieve the documents from
        :type retrieve: str
        :param dict_filter: dict representing a filter see pyMongo doc
        :type dict_filter: dict
        :param sort: Field to sort on or list of tuples of field and direction
                    [("field", pymongo.DESCENDING), ("field2", pymongo.DESCENDING)]
        :type sort: list
        :param limit: Can be used to limit the amount of returned results
        :type limit: int
        :param skip: Can be used to skip the first x records of the returned results
        :type skip: int
        :param query_filter: Dict to include fields to return in the query results (e.g.: {field1: 1, field2: 1})
        :type query_filter: dict
        :param sort_dir: DESC (default) for DESCENDING, ASC for ASCENDING
        :type sort_dir: str
        :param id_to_string: Whether to convert mongodb '_id' from an ObjectId to a string
        :type id_to_string: bool
        :return: List of documents saved in the backend
        :rtype: list
        """
        documentlist = []

        if sort is not None:
            if isinstance(sort, str):
                if sort_dir == "DESC":
                    if limit is not None:
                        resultset = (
                            getattr(self, "store_{}".format(retrieve))
                            .find(dict_filter, {"json": 0})
                            .sort(sort, DESCENDING)
                            .limit(limit)
                            .skip(skip)
                        )
                    else:
                        resultset = (
                            getattr(self, "store_{}".format(retrieve))
                            .find(dict_filter, {"json": 0})
                            .sort(sort, DESCENDING)
                            .skip(skip)
                        )
                elif sort_dir == "ASC":
                    if limit is not None:
                        resultset = (
                            getattr(self, "store_{}".format(retrieve))
                            .find(dict_filter, {"json": 0})
                            .sort(sort, ASCENDING)
                            .limit(limit)
                            .skip(skip)
                        )
                    else:
                        resultset = (
                            getattr(self, "store_{}".format(retrieve))
                            .find(dict_filter, {"json": 0})
                            .sort(sort, ASCENDING)
                            .skip(skip)
                        )
            if isinstance(sort, list):
                if limit is not None:
                    resultset = (
                        getattr(self, "store_{}".format(retrieve))
                        .find(dict_filter, {"json": 0})
                        .sort(sort)
                        .limit(limit)
                        .skip(skip)
                    )
                else:
                    resultset = (
                        getattr(self, "store_{}".format(retrieve))
                        .find(dict_filter, {"json": 0})
                        .sort(sort)
                        .skip(skip)
                    )
        else:
            if limit is not None:
                resultset = (
                    getattr(self, "store_{}".format(retrieve))
                    .find(dict_filter, {"json": 0})
                    .limit(limit)
                    .skip(skip)
                )
            else:
                resultset = (
                    getattr(self, "store_{}".format(retrieve))
                    .find(dict_filter, {"json": 0})
                    .skip(skip)
                )

        if query_filter is not None:
            if sort is not None:
                if isinstance(sort, str):
                    if limit is not None:
                        resultset = (
                            getattr(self, "store_{}".format(retrieve))
                            .find(dict_filter, query_filter)
                            .sort(sort, DESCENDING)
                            .limit(limit)
                            .skip(skip)
                        )
                    else:
                        resultset = (
                            getattr(self, "store_{}".format(retrieve))
                            .find(dict_filter, query_filter)
                            .sort(sort, DESCENDING)
                            .skip(skip)
                        )
                if isinstance(sort, list):
                    if limit is not None:
                        resultset = (
                            getattr(self, "store_{}".format(retrieve))
                            .find(dict_filter, query_filter)
                            .sort(sort)
                            .limit(limit)
                            .skip(skip)
                        )
                    else:
                        resultset = (
                            getattr(self, "store_{}".format(retrieve))
                            .find(dict_filter, query_filter)
                            .sort(sort)
                            .skip(skip)
                        )
            else:
                if limit is not None:
                    resultset = (
                        getattr(self, "store_{}".format(retrieve))
                        .find(dict_filter, query_filter)
                        .limit(limit)
                        .skip(skip)
                    )
                else:
                    resultset = (
                        getattr(self, "store_{}".format(retrieve))
                        .find(dict_filter, query_filter)
                        .skip(skip)
                    )

        if id_to_string:
            for doc in resultset:
                doc["_id"] = str(doc["_id"])
                documentlist.append(doc)
        else:
            for doc in resultset:
                documentlist.append(doc)

        return documentlist

    def fetch_one(
        self, retrieve=None, dict_filter={}, query_filter=None, id_to_string=True
    ):
        """
        The fetch one method wraps the original find_one method from pyMongo and turns the _id into a string.

        :param retrieve: Collection name where to retrieve the documents from
        :type retrieve: str
        :param dict_filter: dict representing a filter see pyMongo doc
        :type dict_filter: dict
        :param query_filter: Dict with fields to exclude or include; e.g. {"hosts": 0} or {"hosts": 1}
        :type query_filter: dict
        :param id_to_string: Whether to convert mongodb '_id' from an ObjectId to a string
        :type id_to_string: bool
        :return: Dict with items from database or None
        :rtype: dict or None
        """

        if "_id" in dict_filter:
            if isinstance(dict_filter["_id"], str):
                dict_filter["_id"] = bson.objectid.ObjectId(dict_filter["_id"])
        if query_filter is not None:
            result = getattr(self, "store_{}".format(retrieve)).find_one(
                dict_filter, query_filter
            )
        else:
            result = getattr(self, "store_{}".format(retrieve)).find_one(dict_filter)

        if result is not None:
            if id_to_string:
                result["_id"] = str(result["_id"])

        return result

    def datatables_data_columns_ordering(self, request_values):
        """
        Method responsible for retrieving the column and order details from the DataTables request values

        :param request_values:
        :type request_values:
        :return: 2 Dictionaries namely: the column details and order details
        :rtype: defaultdict, defaultdict
        """
        col = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))
        order = defaultdict(lambda: defaultdict(dict))

        col_regex = re.compile(r"columns\[(\d*)\]\[(\w*)\](?:\[(\w*)\])?")
        order_regex = re.compile(r"order\[(\d*)\]\[(\w*)\]")

        for each in sorted(request_values.keys()):
            check_col_match = col_regex.match(each)
            check_order_match = order_regex.match(each)
            if check_col_match:
                if check_col_match.group(2) == "search":
                    try:
                        col[check_col_match.group(1)][check_col_match.group(2)][
                            check_col_match.group(3)
                        ] = int(request_values[each])
                    except ValueError:
                        col[check_col_match.group(1)][check_col_match.group(2)][
                            check_col_match.group(3)
                        ] = request_values[each]
                else:
                    col[check_col_match.group(1)][
                        check_col_match.group(2)
                    ] = request_values[each]
            if check_order_match:
                order[check_order_match.group(1)][
                    check_order_match.group(2)
                ] = request_values[each]

        return col, order

    def datatables_data_filter(self, request_values, columns, additional_filters):
        """
        Method responsible for retrieving the filter values entered in the search box of the DataTables.

        :param request_values:
        :type request_values:
        :param columns:
        :type columns:
        :param additional_filters:
        :type additional_filters:
        :return: Prepared filter based on filterable columns and retrieved search value
        :rtype: dict
        """
        docfilter = defaultdict(list)

        search_val = request_values["search[value]"]

        if search_val != "":

            try:
                regex = re.compile(search_val, re.IGNORECASE)

                # get list with searchable columns
                column_search_list = [
                    columns[i]["data"]
                    for i in columns
                    if columns[i]["searchable"]
                ]

                for each in column_search_list:
                    docfilter["$or"].append({each: {"$regex": regex}})

            except sre_constants.error:
                pass

        if additional_filters is not None:
            docfilter["$and"] = additional_filters

        # create an additional column filter with entries in the columns[x]['search']['value']

        colfilter = {
            columns[key]["data"]: columns[key]["search"]["value"]
            for (key, value) in columns.items()
            if (
                columns[key]["search"]["value"] != ""
                and columns[key]["search"]["regex"] == "false"
            )
        }

        colregexfilter = {
            columns[key]["data"]: {"$regex": columns[key]["search"]["value"]}
            for (key, value) in columns.items()
            if (
                columns[key]["search"]["value"] != ""
                and columns[key]["search"]["regex"] == "true"
            )
        }

        if len(colfilter) != 0:
            docfilter["$and"].append(colfilter)

        if len(colregexfilter) != 0:
            docfilter["$and"].append(colregexfilter)

        return docfilter

    def datatables_data_order(self, ordering, columns):
        """
        Method responsible for setting up the column sorting.

        :param ordering:
        :type ordering:
        :param columns:
        :type columns:
        :return: list with sorting instructions
        :rtype: list
        """

        sort = []

        for each in ordering:
            if ordering[each]["dir"] == "asc":
                sort.append(
                    (
                        columns[ordering[each]["column"]]["data"],
                        pymongo.ASCENDING,
                    )
                )
            else:
                sort.append(
                    (
                        columns[ordering[each]["column"]]["data"],
                        pymongo.DESCENDING,
                    )
                )

        return sort

    def addUser(self, user, pwd, admin=False, localOnly=False):
        hashed = generate_password_hash(pwd, method="pbkdf2:sha512")
        entry = {"username": user, "password": hashed}
        if admin:
            entry["master"] = True
        if localOnly:
            entry["local_only"] = True
        self.user_store.insert(entry)

    def changePassword(self, user, pwd):
        hashed = generate_password_hash(pwd, method="pbkdf2:sha512")
        self.user_store.update({"username": user}, {"$set": {"password": hashed}})

    def verifyUser(self, user, pwd):
        person = self.getUser(user)
        return person and check_password_hash(person["password"], pwd)

    def deleteUser(self, user):
        self.user_store.remove({"username": user})

    def setAdmin(self, user, admin=True):
        if admin:
            self.user_store.update({"username": user}, {"$set": {"master": True}})
        else:
            self.user_store.update({"username": user}, {"$unset": {"master": ""}})

    def setLocalOnly(self, user, localOnly=True):
        if localOnly:
            self.user_store.update({"username": user}, {"$set": {"local_only": True}})
        else:
            self.user_store.update({"username": user}, {"$unset": {"local_only": ""}})

    def isMasterAccount(self, user):
        return (
            False
            if self.user_store.find({"username": user, "master": True}).count() == 0
            else True
        )

    def userExists(self, user):
        return True if self.user_store.count_documents({"username": user}) > 0 else False

    def isSingleMaster(self, user):
        return True if self.user_store.count_documents({"username": {"$ne": user}, "master": True}) > 0 else False

    def getUser(self, user):
        return sanitize(self.user_store.find_one({"username": user}))
