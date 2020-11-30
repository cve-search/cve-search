import logging
import re
from collections import defaultdict

from flask import (
    render_template,
    request,
    jsonify,
    url_for,
)
from flask_breadcrumbs import register_breadcrumb, default_breadcrumb_root

from lib.CVEs import CveHandler
from lib.DatabaseHandler import DatabaseHandler
from lib.DatabaseLayer import (
    getCWEs,
    getCAPECFor,
    getCAPEC,
    cvesForCPE,
    getSearchResults,
    via4Linked,
)
from lib.LogHandler import AppLogger
from . import home
from .utils import (
    defaultFilters,
    config_args,
    get_plugins,
    markCPEs,
    plugManager,
    pluginArgs,
    generate_full_query,
)
from ..helpers.server_side_datatables import ServerSideDataTable
from ..run import app

logging.setLoggerClass(AppLogger)

logger = logging.getLogger(__name__)

DATATABLE_FILTER = defaultFilters

default_breadcrumb_root(home, ".")

dbh = DatabaseHandler()


@home.route("/", methods=["GET"])
@register_breadcrumb(home, ".", "Home")
def index():
    return render_template("index.html", **config_args)


def view_vendor_name(*args, **kwargs):

    try:
        return [
            {"text": "Vendor-List", "url": "/browse",},
            {
                "text": "{}".format(request.view_args["vendor"]),
                "url": "/browse/{}".format(request.view_args["vendor"]),
            },
        ]
    except KeyError:
        return [{"text": "Vendor-List", "url": "/browse",}]


@home.route("/browse")
@home.route("/browse/<vendor>")
@register_breadcrumb(home, ".browse", "", dynamic_list_constructor=view_vendor_name)
def browse_vendor(vendor=None):
    if vendor is None:

        return render_template(
            "browse_vendor.html"
        )

    else:
        data = {
            "vendor": vendor,
            "product": [
                x
                for x in dbh.connection.store_cves.distinct(
                    "products", {"vendors": vendor}
                )
                if x is not None
            ],
        }

        return render_template(
            "browse.html", product=data["product"], vendor=data["vendor"]
        )


@home.route("/browse/fetch_data", methods=["POST"])
def browse_fetch_data():

    retdata = {
        "data": [{"vendors": x} for x in dbh.connection.store_cves.distinct("vendors") if x is not None],
    }

    return retdata


def view_cve_id_name(*args, **kwargs):
    return [
        {
            "text": request.view_args["cve_id"],
            "url": "/cve/{}".format(request.view_args["cve_id"]),
        }
    ]


@home.route("/cve/<cve_id>")
@register_breadcrumb(home, ".cve", "", dynamic_list_constructor=view_cve_id_name)
def cve(cve_id):
    cvesp = CveHandler(
        rankinglookup=True,
        namelookup=True,
        via4lookup=True,
        capeclookup=True,
        subscorelookup=True,
    )
    cve = cvesp.getcve(cveid=cve_id.upper())
    if cve is None:
        return render_template(
            "error.html", status={"except": "cve-not-found", "info": {"cve": cve_id}}
        )

    if app.config["WebInterface"]:
        cve = markCPEs(cve)

        plugManager.onCVEOpen(cve_id, **pluginArgs)
        pluginData = plugManager.cvePluginInfo(cve_id, **pluginArgs)
        return render_template("cve.html", cve=cve, plugins=pluginData)
    else:
        return render_template("cve.html", cve=cve)


def view_cwe_id_name(*args, **kwargs):

    try:
        return [
            {"text": "CWE-List", "url": "/cwe",},
            {
                "text": "CWE-{}".format(request.view_args["cwe_id"]),
                "url": "/cwe/{}".format(request.view_args["cwe_id"]),
            },
        ]
    except KeyError:
        return [{"text": "CWE-List", "url": "/cwe",}]


@home.route("/cwe")
@home.route("/cwe/<cwe_id>")
@register_breadcrumb(home, ".cwe", "", dynamic_list_constructor=view_cwe_id_name)
def get_cwe(cwe_id=None):
    data = getCWEs()
    if cwe_id is None:
        cwes = [x for x in data if x["weaknessabs"].lower() == "class"]
        return render_template("cwe.html", cwes=cwes, capec=None)
    else:
        cwes = {x["id"]: x["name"] for x in data}
        return render_template(
            "cwe.html", cwes=cwes, cwe=cwe_id, capec=getCAPECFor(cwe_id), minimal=True,
        )


def view_capec_id_name(*args, **kwargs):

    return [
        {
            "text": "CAPEC-{}".format(request.view_args["capec_id"]),
            "url": "/capec/{}".format(request.view_args["capec_id"]),
        }
    ]


@home.route("/capec/<capec_id>")
@register_breadcrumb(home, ".capec", "", dynamic_list_constructor=view_capec_id_name)
def capec(capec_id):
    data = getCWEs()
    cwes = {x["id"]: x["name"] for x in data}

    req_capec = getCAPEC(capec_id)

    rel_capecs = defaultdict(dict)

    if len(req_capec["related_capecs"]) != 0:
        for each in req_capec["related_capecs"]:
            rel_capecs[each] = getCAPEC(each)["summary"]

    return render_template(
        "capec.html", cwes=cwes, capecs=dict(rel_capecs), capec=req_capec
    )


@home.route("/_get_plugins")
def fetch_plugins():

    plugins = get_plugins()

    return jsonify({"plugins": plugins})


def view_product_name(*args, **kwargs):
    vendor = request.view_args["vendor"]

    return [
        {
            "text": "{}".format(request.view_args["product"]),
            "url": "/search/{}/{}".format(vendor, request.view_args["product"]),
        }
    ]


@home.route("/search/<vendor>/<path:product>")
@register_breadcrumb(
    home, ".browse.vendor", "", dynamic_list_constructor=view_product_name
)
def search(vendor=None, product=None):
    search = (vendor, product)
    cve = cvesForCPE(search, strict_vendor_product=True)
    return render_template("search.html", vendor=vendor, product=product, cve=cve)


@home.route("/search", methods=["GET", "POST"])
def freetext_search():
    search = request.form.get("search")
    if search == "":
        return url_for("home.index")
    result = getSearchResults(search)
    cve = {"results": result["data"], "total": len(result["data"])}
    errors = result["errors"] if "errors" in result else []
    return render_template(
        "search.html", cve=cve, errors=errors, freetextsearch=search,
    )


def view_linked(*args, **kwargs):
    key = request.view_args["key"]

    return [
        {
            "text": "{}".format(request.view_args["value"]),
            "url": "/link/{}/{}".format(key, request.view_args["value"]),
        }
    ]


@home.route("/link/<key>/<value>")
@register_breadcrumb(home, ".linked", "", dynamic_list_constructor=view_linked)
def link(key=None, value=None):
    regex = re.compile(re.escape(value), re.I)
    cve = via4Linked(key, regex)
    cvssList = [float(x["cvss"]) for x in cve["results"] if x.get("cvss")]
    if cvssList:
        stats = {
            "maxCVSS": max(cvssList),
            "minCVSS": min(cvssList),
            "count": int(cve["total"]),
        }
    else:
        stats = {"maxCVSS": 0, "minCVSS": 0, "count": int(cve["total"])}
    return render_template(
        "linked.html",
        via4map=key.split(".")[0],
        field=".".join(key.split(".")[1:]),
        value=value,
        cve=cve,
        stats=stats,
    )


@home.route("/set_filter", methods=["POST"])
def set_filter():
    global DATATABLE_FILTER

    filter_params = dict(request.json)

    logger.debug("Received filter parameters: {}".format(filter_params))

    DATATABLE_FILTER = filter_params

    return "SET"


@home.route("/reset_filter")
def reset_filter():
    global DATATABLE_FILTER

    DATATABLE_FILTER = defaultFilters

    return "SET"


@home.route("/get_filter")
def get_filter():
    global DATATABLE_FILTER

    if DATATABLE_FILTER == defaultFilters:
        return jsonify(True)
    else:
        return jsonify(False)


@home.route("/fetch_cve_data", methods=["POST"])
def fetch_cvedata():
    global DATATABLE_FILTER

    logger.debug("Current filters set to: {}".format(DATATABLE_FILTER))

    if DATATABLE_FILTER == defaultFilters:
        ssd = ServerSideDataTable(request=request, backend=dbh.connection)
    else:
        query_filters = generate_full_query(DATATABLE_FILTER)
        if len(query_filters) != 0:
            ssd = ServerSideDataTable(
                request=request,
                backend=dbh.connection,
                additional_filters=query_filters,
            )
        else:
            ssd = ServerSideDataTable(request=request, backend=dbh.connection)

    return_data = ssd.output_result()

    return return_data
