import calendar
from datetime import datetime

date_time_formats = [
    "%d-%m-%Y",
    "%Y-%m-%d",
    "%d-%m-%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%H:%M:%S %d-%m-%Y",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S,%f",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S,%fZ",
]


def timestringTOdatetime(timestring):
    """
    Method to convert a given date time string into a datetime object. Timestring is matched to the date_time_formats
    'date time string formats' list. If matched will return a datetime object; will return False otherwise.

    :param timestring: date time string
    :type timestring: str
    :return: Datetime object
    :rtype: datetime
    """

    match = False

    # try to match string formats to given string
    for each in date_time_formats:
        try:
            match = datetime.strptime(timestring, each)
        except ValueError:
            continue

    return match


def datetimeTOtimestamp(date_time_object):
    """
    Method that will take the provided date time and converts it into a timestamp

    :param date_time_object: date time object
    :type date_time_object: datetime
    :return: unix timestamp
    :rtype: int
    """

    return calendar.timegm(date_time_object.utctimetuple())


def timestampTOdatetime(timestamp):
    """
    Method that will take the provided timestamp and converts it into a date time object

    :param timestamp: unix timestamp
    :type timestamp: int
    :return: date time object
    :rtype: datetime
    """
    value = datetime.utcfromtimestamp(timestamp)

    return value
