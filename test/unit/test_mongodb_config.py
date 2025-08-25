import os
import pytest
from lib.Config import Configuration

test_cases = [
    pytest.param(
        {
            "username": "user",
            "password": "pass",
            "dns_srv": "True",
            "expected_uri": "mongodb+srv://user:pass@localhost/testdb?authSource=admin&retryWrites=true&w=majority",
            "expected_dbapi": "srv",
        },
        id="srv_with_auth",
    ),
    pytest.param(
        {
            "username": "user",
            "password": "pass",
            "dns_srv": "False",
            "expected_uri": "mongodb://user:pass@localhost:27017/testdb?authSource=admin",
            "expected_dbapi": None,
        },
        id="no_srv_with_auth",
    ),
    pytest.param(
        {
            "username": "",
            "password": "",
            "dns_srv": "True",
            "expected_uri": "mongodb+srv://localhost/testdb?retryWrites=true&w=majority",
            "expected_dbapi": "srv",
        },
        id="srv_no_auth",
    ),
    pytest.param(
        {
            "username": "",
            "password": "",
            "dns_srv": "False",
            "expected_uri": "mongodb://localhost:27017/testdb",
            "expected_dbapi": None,
        },
        id="no_srv_no_auth",
    ),
]

ENV_VARS = [
    "DATASOURCE_HOST",
    "DATASOURCE_PORT",
    "DATASOURCE_DBNAME",
    "DATASOURCE_DBAPI",
    "DATASOURCE_USER",
    "DATASOURCE_PASSWORD",
]


def _init_config(case, monkeypatch):
    """Helper to set up Configuration and clear environment for a test case."""
    # Clear environment
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    # Use real DB settings for tests that only verify configuration
    monkeypatch.delenv("USE_TEST_DB", raising=False)

    # Ensure Database section exists
    if not Configuration.ConfigParser.has_section("Database"):
        Configuration.ConfigParser.add_section("Database")

    # Set test values in the class parser
    Configuration.ConfigParser.set("Database", "Host", "localhost")
    Configuration.ConfigParser.set("Database", "Port", "27017")
    Configuration.ConfigParser.set("Database", "DB", "testdb")
    Configuration.ConfigParser.set("Database", "Username", case["username"])
    Configuration.ConfigParser.set("Database", "Password", case["password"])
    Configuration.ConfigParser.set("Database", "DnsSrvRecord", case["dns_srv"])
    Configuration.ConfigParser.set("Database", "AuthDB", "admin")


@pytest.mark.parametrize("case", test_cases)
def test_mongodb_config_url_generation(case, monkeypatch):
    """Tests that MongoDB URLs are built correctly for internal use."""
    _init_config(case, monkeypatch)
    uri = Configuration.getMongoUri()
    assert uri == case["expected_uri"]


@pytest.mark.parametrize("case", test_cases)
def test_mongodb_config_envvar_passing(case, monkeypatch):
    """Tests that MongoDB configuration is properly passed via environment variables."""
    _init_config(case, monkeypatch)
    Configuration.setMongoDBEnv()

    assert os.environ["DATASOURCE_HOST"] == "localhost"
    assert os.environ["DATASOURCE_PORT"] == "27017"
    assert os.environ["DATASOURCE_DBNAME"] == "testdb"

    if case["expected_dbapi"]:
        assert os.environ["DATASOURCE_DBAPI"] == case["expected_dbapi"]
    else:
        assert "DATASOURCE_DBAPI" not in os.environ

    if case["username"] and case["password"]:
        assert os.environ["DATASOURCE_USER"] == case["username"]
        assert os.environ["DATASOURCE_PASSWORD"] == case["password"]
    else:
        assert "DATASOURCE_USER" not in os.environ
        assert "DATASOURCE_PASSWORD" not in os.environ
