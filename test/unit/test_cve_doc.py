import pytest

from test.runners.cli_test_runner import CLITestRunner


@pytest.fixture
def runner():
    return CLITestRunner()


def test_cve_doc(runner):

    result = runner.runcommand("bin/cve_doc.py")

    test_results = result.stdout.replace("\n", "")

    assert result.returncode == 0
    assert test_results[105:118] == "CVE-2015-0001"
