"""
server_side_datatables.py
=========================
"""
from collections import namedtuple, defaultdict


class ServerSideDataTable(object):
    """
    This class holds all the logic for enabling and handling server side DataTables within the application

    :param request: The post (or get) parameters send by the client side of DataTables
    :type request: flask.request
    :param backend: Handler to the backend
    :type backend: DatabasePluginBase
    """

    def __init__(self, request, backend, additional_filters=None):

        self.request_values = request.values

        self.backend = backend

        self.additional_filters = additional_filters

        self.columns, self.ordering, self.results, self.fields, self.data_length = (
            None,
            None,
            None,
            None,
            None,
        )

        self.total, self.total_filtered, self.current_draw = 0, 0, 0

        self.filtered = {}

        self.sort = []

        self._pre_fetch_processing()

    def output_result(self):

        retdata = {
            "draw": int(self.current_draw),
            "recordsTotal": int(self.total),
            "recordsFiltered": int(self.total_filtered),
            "data": self.results,
        }

        return retdata

    def _pre_fetch_processing(self):
        """
        Method to provision the necessary variables for the correct retrieval of the results from the MongoDB Database
        """

        self.current_draw = int(self.request_values["draw"])

        self.data_length = self.__data_dimension()

        self.columns, self.ordering = self.backend.datatables_data_columns_ordering(
            self.request_values
        )

        self.sort = self.backend.datatables_data_order(self.ordering, self.columns)

        self.fields = defaultdict(int)

        for each in self.columns:
            self.fields[self.columns[each]["data"]] = 1

        if len(self.sort) == 0:
            self.sort = None

        if self.additional_filters is not None:
            self.total = self.backend.count(
                self.request_values["retrieve"], self.additional_filters
            )
        else:
            self.total = self.backend.count(self.request_values["retrieve"])

        self.filtered = self.backend.datatables_data_filter(
            self.request_values, self.columns, self.additional_filters
        )

        self._fetch_results()

        if len(self.filtered) != 0:
            self.total_filtered = self.backend.count(
                self.request_values["retrieve"], self.filtered
            )
        else:
            self.total_filtered = self.total

    def _fetch_results(self):
        """
        Method responsible for querying the backend and fetching the results from the database
        """
        self.results = self.backend.query_docs(
            retrieve=self.request_values["retrieve"],
            dict_filter=self.filtered,
            query_filter=self.fields,
            sort=self.sort,
            limit=self.data_length.length,
            skip=self.data_length.start,
        )

    def __data_dimension(self):
        """
        Method responsible for retrieving the requested start and length parameters from the DataTables request values

        :return: Namedtuple 'data_length' with a start and length attribute
        :rtype: namedtuple
        """

        data_length = namedtuple("data_length", ["start", "length"])

        data_length.start = int(self.request_values["start"])
        data_length.length = int(self.request_values["length"])

        return data_length
