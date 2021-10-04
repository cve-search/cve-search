import logging
from abc import ABC, abstractmethod
from datetime import datetime

from lib.LogHandler import AppLogger

logging.setLoggerClass(AppLogger)


def convertDatetime(dct=None):
    if isinstance(dct, (list, tuple, set)):
        for item in dct:
            convertDatetime(item)
    elif type(dct) is dict:
        for key, val in dct.items():
            if isinstance(val, datetime):
                dct[key] = val.isoformat()
            if isinstance(val, (dict, list)):
                convertDatetime(val)
    return dct


class ApiRequest(ABC):
    def __init__(self):
        self._request_results = None

    @abstractmethod
    def process(self, **kwargs):
        raise NotImplementedError

    @property
    def request_results(self):
        return self._request_results

    @request_results.setter
    def request_results(self, the_results):
        self._request_results = {"total": len(the_results), "data": the_results}


class JSONApiRequest(ApiRequest):
    def __init__(self, headers, body):
        """
        Main class for the JSONApiRequest endpoints of the api.

        :param headers: Request headers
        :type headers: dict
        :param body: JSON query body
        :type body: dict
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)

        self.request_headers = headers
        self.body = body

    def process(self, database_connection):
        """
        Method to process the request

        :param database_connection: Hookup to the database
        :type database_connection: DatabaseHandler
        :return: Results from the request
        :rtype: list
        """
        self.logger.debug(
            "Processing request: {}  Headers received: {}".format(
                self.body, self.request_headers
            )
        )

        validated, reason = self.validate_body()

        if not validated:
            self.logger.warning(
                "Validation on {} not succeeded: {}".format(self.body, reason)
            )
            return reason, 400
        else:

            results = database_connection.query_docs(**self.body)

            self.logger.debug(
                "Retrieving from: {} -- records: {}".format(self.body["retrieve"], len(results))
            )

            self.request_results = results

            return convertDatetime(dct=self.request_results)

    def validate_body(self):
        """
        Method for validating the request body.

        :return:
        :rtype:
        """
        retrieve = ["capec", "cpe", "cves", "cwe", "via4"]

        sort_dir = ["ASC", "DESC"]

        required_keys = ["retrieve", "dict_filter"]

        optional_keys = [
            "sort",
            "limit",
            "skip",
            "query_filter",
            "sort_dir",
        ]

        if self.body is None or len(self.body) == 0:
            return (
                False,
                "Please send a proper request with a json formatted like in the documentation.",
            )

        if not all(key.lower() in self.body for key in required_keys):
            return False, "Request is missing one or more required keys!"

        if not self.body["retrieve"].lower() in retrieve:
            return False, "Unable to retrieve from specified data source!"

        if "sort_dir" in self.body.keys():
            if not self.body["sort_dir"] in sort_dir:
                return (
                    False,
                    "Specified sorting direction not possible; possible options are: {}!".format(
                        sort_dir
                    ),
                )

        all_keys = retrieve + required_keys + optional_keys

        if not all(key in all_keys for key in self.body):
            return False, "Request contains unknown keys!"

        if "skip" in self.body:
            try:
                self.body["skip"] = int(self.body["skip"])
            except ValueError:
                return False, "Skip parameter is not a integer!"

        if "limit" in self.body:
            try:
                self.body["limit"] = int(self.body["limit"])
            except ValueError:
                return False, "Limit parameter is not a integer!"

        return True, "Ok"
