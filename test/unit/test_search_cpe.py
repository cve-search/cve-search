import pytest

from test.runners.cli_test_runner import CLITestRunner


@pytest.fixture
def runner():
    return CLITestRunner()


def test_search_cpe(runner):

    result = runner.runcommand("bin/search_cpe.py -s wordpress")

    resultlist = result.stdout.split("\n")

    assert result.returncode == 0

    # check if wordpress is matched in returned results; first, somewhere middle and somewhere last
    first_val = resultlist[0][41:].lower()
    middle_val = resultlist[int(len(resultlist) / 2)][41:].lower()
    last_val = resultlist[-1][41:].lower()
    if last_val == "":
        last_val = resultlist[-2][41:].lower()

    assert "wordpress" in first_val
    assert "wordpress" in middle_val
    assert "wordpress" in last_val


def test_search_cpe_json(runner):

    result = runner.runcommand("bin/search_cpe.py -s wordpress -o json")

    assert result.returncode == 0


def test_search_cpe_compact(runner):

    result = runner.runcommand("bin/search_cpe.py -s wordpress -o compact")

    assert result.returncode == 0


def test_search_cpe_csv(runner):

    result = runner.runcommand("bin/search_cpe.py -s wordpress -o csv")

    assert result.returncode == 0
