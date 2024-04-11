import json

import pytest

from test.runners.cli_test_runner import CLITestRunner


@pytest.fixture
def runner():
    return CLITestRunner()


def test_search(runner):
    result = runner.runcommand("bin/search.py -p cisco:ios:12.4")

    assert result.returncode == 0
    assert result.stdout[:20] == "CVE\t: CVE-2017-12231"


def test_search_lax(runner):
    result = runner.runcommand("bin/search.py -p cisco:ios:12.4 --lax")

    assert result.returncode == 0
    assert result.stdout[:20] == "CVE\t: CVE-2017-12231"


def test_search_lax_alphanumeric_version(runner):
    result = runner.runcommand("bin/search.py -p juniper:junos:15.1x53 --lax")

    assert result.returncode == 0
    assert result.stdout.startswith(
        "Notice: Target version 15.1x53 simplified as 15.1.0.53 "
    )
    assert result.stdout.splitlines()[2] == "CVE\t: CVE-2018-0004"


def test_search_lax_complex_version_simplification(runner):
    result = runner.runcommand('bin/search.py -p "cisco:ios:15.6\(2\)sp2a" --lax')

    assert result.returncode == 0
    assert result.stdout.splitlines()[0].find(" simplified as 15.6.0.2.0.2.0 ") > 0


def test_search_lax_wildcard_version(runner):
    result = runner.runcommand("bin/search.py -p juniper:junos:* --lax")

    assert result.returncode == 0
    # A '0' is a fine simplification for a wildcard as zero is below any version.
    assert result.stdout.startswith("Notice: Target version * simplified as 0 ")
    assert result.stdout.splitlines()[2] == "CVE\t: CVE-2018-0004"


def test_search_lax_missing_version(runner):
    result = runner.runcommand("bin/search.py -p juniper:junos --lax")

    assert result.returncode == 1


def test_search_if_vuln(runner):
    result = runner.runcommand("bin/search.py -p cisco:ios:12.4 --only-if-vulnerable")

    assert result.returncode == 0
    assert result.stdout[:20] == "CVE\t: CVE-2017-12231"


def test_search_json(runner):
    result = runner.runcommand(
        "bin/search.py -p cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:*:* -o json"
    )

    assert result.returncode == 0
    res = json.loads(result.stdout)

    assert res["id"] == "CVE-2017-0123"


def test_search_html(runner):
    result = runner.runcommand(
        "bin/search.py -p cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:*:* -o html"
    )

    assert result.returncode == 0
    assert result.stdout[:6] == "<html>"


def test_search_xml(runner):
    result = runner.runcommand(
        "bin/search.py -p cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:*:* -o xml"
    )

    assert result.returncode == 0
    assert result.stdout[0:39] == '<?xml version="1.0" encoding="UTF-8" ?>'


def test_search_cveid(runner):
    result = runner.runcommand(
        "bin/search.py -p cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:*:* -o cveid"
    )

    assert result.returncode == 0
    assert result.stdout == "CVE-2017-0123\n"


def test_search_cveid_desc(runner):
    result = runner.runcommand(
        "bin/search.py -p cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:*:* -o csv -l"
    )

    assert result.returncode == 0
    assert (
        result.stdout[:60]
        == "CVE-2017-0123|2017-03-17 00:59:00|4.3|Uniscribe in Microsoft"
    )


def test_search_nra(runner):
    result = runner.runcommand("bin/search.py -p openstack:keystone -n -r -a")

    assert result.returncode == 0
    assert result.stdout[:19] == "CVE\t: CVE-2013-0270"


def test_search_vendor(runner):
    result = runner.runcommand(
        "bin/search.py -p microsoft:windows_7 --strict_vendor_product"
    )

    assert result.returncode == 0
    assert result.stdout[:19] == "CVE\t: CVE-2017-0123"


def test_search_summary(runner):
    result = runner.runcommand("bin/search.py -s flaw -i 1")

    assert result.returncode == 0


def test_search_ti(runner):
    result = runner.runcommand("bin/search.py -p microsoft:windows_7 -t 30 -i 1")

    assert result.returncode == 0


# def test_search_cve(runner):
#     result = runner.runcommand("bin/search.py -c CVE-2010-3333")
#
#     assert result.returncode == 0
#     assert result.stdout[:19] == "CVE\t: CVE-2010-3333"
