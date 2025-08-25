import os
import pytest
from lib.Config import Configuration
from test.test_data.testdata import data


@pytest.fixture(scope="session", autouse=True)
def prepare_test_db():
    """
    Prepare a clean test database and populate it with test data.
    Runs once per test session.
    """
    # Ensure the scripts use the test database
    os.environ["USE_TEST_DB"] = "1"

    db = Configuration.getMongoConnection()

    # Clean all existing collections
    for coll_name in db.list_collection_names():
        db[coll_name].drop()

    # Insert test data
    for coll_name, docs in data.items():
        if docs:
            db[coll_name].insert_many(docs)

    yield db

    # Clean up after the session
    for coll_name in db.list_collection_names():
        db[coll_name].drop()
