import pytest

from test.runners.web_test_runner import WebTestRunner
from bs4 import BeautifulSoup


@pytest.fixture
def webrunner():
    return WebTestRunner(address=("localhost", 443))


def test_web_up(webrunner):
    result = webrunner.call(method="GET", resource="/")

    soup = BeautifulSoup(result.text, features="html.parser")

    assert result.status_code == 200
    assert soup.find("title").text == "Most recent entries - CVE-Search"
