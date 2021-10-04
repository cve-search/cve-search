import pytest

from test.runners.cli_test_runner import CLITestRunner


@pytest.fixture
def runner():
    return CLITestRunner()


def test_db_dump(runner):

    result = runner.runcommand("bin/db_dump.py -l 1 -r -v -c")

    assert result.returncode == 0
