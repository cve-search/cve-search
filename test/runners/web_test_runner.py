import json
from json import JSONDecodeError

import requests


class WebTestRunner(object):
    """
    The WebTestRunner class serves as a base class for all API's used within the tests
    """

    def __init__(self, address, api_path=None, proxies={}, protocol="https"):
        """
        The WebTestRunner caller handles all communication towards a api resource.

        :param address: Tuple with host ip/name and port
        :type address: tuple
        :param api_path: Generic to connect to api resources, defaults to 'None'
        :type api_path: str
        :param proxies: If you need to use a proxy, you can configure individual requests with the proxies argument
                        to any request method
        :type proxies: dict
        :param protocol: Protocol to use when connecting to api; defaults to 'https'
        :type protocol: str
        """

        if not isinstance(address, tuple):
            raise TypeError(
                "The parameter 'address' has to be a tuple with the address and port of the api host"
                "e.g. ('127.0.0.1', 8834) "
            )

        self.verify = False
        self.server = address[0]
        self.port = address[1]
        self.protocol = protocol
        self.baseurl = "{}://{}:{}".format(self.protocol, self.server, self.port)
        self.api_path = api_path
        self.proxies = proxies

        self.myheaders = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
        }

    def __repr__(self):
        """return a string representation of the obj GenericApi"""
        return "<<WebTestRunner:({}, {})>>".format(self.server, self.port)

    def __del__(self):
        """Called when the class is garbage collected."""
        pass

    def __build_url(self, resource):
        """
        Internal method to build a url to use when executing commands

        :param resource: API end point to connect to
        :type resource: str
        :return: url string
        :rtype: str
        """
        if self.api_path is None:
            return "{0}/{1}".format(self.baseurl, resource)
        else:
            return "{0}/{1}/{2}".format(self.baseurl, self.api_path, resource)

    def __connect(self, method, resource, session, data=None, timeout=60):
        """
        Send a request

        Send a request to api host based on the specified data. Specify the content type as JSON and
        convert the data to JSON format.

        :param method: http method to use (e.g. POST, GET, DELETE, PUT)
        :type method: str
        :param resource: API end point to connect to
        :type resource: str
        :param session: Session object from requests library
        :type session: object
        :param data: Request body data
        :type data: dict
        :param timeout: Set the timeout on a request, defaults to 60 seconds
        :type timeout: int
        :return: response from the server
        :rtype: dict
        """

        requests.packages.urllib3.disable_warnings()

        if data is None:
            request_api_resource = {
                "headers": self.myheaders,
                "verify": self.verify,
                "timeout": timeout,
                "proxies": self.proxies,
            }
        else:
            data = json.dumps(data)
            request_api_resource = {
                "data": data,
                "headers": self.myheaders,
                "verify": self.verify,
                "timeout": timeout,
                "proxies": self.proxies,
            }

        if method == "POST":
            r = session.post(self.__build_url(resource), **request_api_resource)
        elif method == "PUT":
            r = session.put(self.__build_url(resource), **request_api_resource)
        elif method == "DELETE":
            r = session.delete(self.__build_url(resource), **request_api_resource)
        else:
            r = session.get(self.__build_url(resource), **request_api_resource)

        try:
            json_response = json.loads(r.text)
        except JSONDecodeError:
            json_response = r

        return json_response

    def call(self, method=None, resource=None, data=None):
        """
        Method for requesting free format api resources

        :param method: http method to use (e.g. POST, GET, DELETE, PUT)
        :type method: str
        :param resource: API end point to connect to
        :type resource: str
        :param data: Request body data
        :type data: dict
        :return: query result
        :rtype: dict
        """
        try:
            with requests.Session() as session:
                result = self.__connect(
                    method=method, resource=resource, session=session, data=data
                )
                return result
        except requests.ConnectionError:
            print("Connection error, is the host up?")
            raise

    @property
    def headers(self):
        """
        Property to return the current headers

        :return: self.myheaders
        :rtype: dict
        """

        return self.myheaders

    def set_header_field(self, field, value):
        """
        Method to add a header and set it's value

        :param field: Name of the header field to add
        :type field: str
        :param value: Value of the header field
        :type value: str
        :return: self.myheaders
        :rtype: dict
        """

        self.myheaders[field] = value

        return self.myheaders

    def del_header_field(self, field):
        """
        Method to delete a header field

        :param field: Name of the header field to delete
        :type field: str
        :return: self.myheaders
        :rtype: dict
        """

        self.myheaders.pop(field)

        return self.myheaders

    def reset_headers(self):
        """
        Method to reset the headers to the default values
        """

        self.myheaders = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
        }
