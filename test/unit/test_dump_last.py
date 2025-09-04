import pytest

from test.runners.cli_test_runner import CLITestRunner


@pytest.fixture
def runner():
    return CLITestRunner()


def test_dump_last_atom(runner):
    result = runner.runcommand("bin/dump_last.py -f atom -l 9")

    test_results = result.stdout.replace("\n", "")

    assert result.returncode == 0
    assert test_results[39:81] == '<feed xmlns="http://www.w3.org/2005/Atom">'
    assert test_results[99:109] == "Last 9 CVE"


def test_dump_last_rss1(runner):
    result = runner.runcommand("bin/dump_last.py -f rss1 -l 9")

    assert result.returncode == 0


def test_dump_last_rss2(runner):
    result = runner.runcommand("bin/dump_last.py -f rss2 -l 9")

    assert result.returncode == 0
    assert (
        result.stdout.replace("\n", "")[0:58]
        == '<?xml version="1.0" encoding="UTF-8" ?><rss version="2.0">'
    )


def test_dump_last_html(runner):
    result = runner.runcommand("bin/dump_last.py -f html -l 9")

    assert result.returncode == 0
    assert result.stdout[:6] == "<html>"


def test_dump_last_with_capec_and_cveranking(runner):
    result = runner.runcommand("bin/dump_last.py -f atom -c -r -l 9")

    assert result.returncode == 0
