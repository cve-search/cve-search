import re
from collections import defaultdict

from flask import render_template, request, make_response, json, jsonify, url_for
from flask_breadcrumbs import register_breadcrumb, default_breadcrumb_root
from flask_login import current_user

from lib.CVEs import CveHandler
from . import home
from .utils import (
    defaultFilters,
    config_args,
    markCPEs,
    generate_full_query,
    validateFilter,
    SanitizeUserInput,
)
from ..helpers.server_side_datatables import ServerSideDataTable
from ..run import app

default_breadcrumb_root(home, ".")


@home.route("/", methods=["GET"])
@register_breadcrumb(home, ".", "Home")
def index():
    return render_template("index.html", **config_args)


def view_vendor_name(*args, **kwargs):
    try:
        return [
            {"text": "Vendor-List", "url": "{}browse".format(url_for("home.index"))},
            {
                "text": "{}".format(request.view_args["vendor"]),
                "url": "{}browse/{}".format(
                    url_for("home.index"), request.view_args["vendor"]
                ),
            },
        ]
    except KeyError:
        return [{"text": "Vendor-List", "url": "browse"}]


@home.route("/browse")
@home.route("/browse/<vendor>")
@register_breadcrumb(home, ".browse", "", dynamic_list_constructor=view_vendor_name)
def browse_vendor(vendor=None):
    if vendor is None:
        return render_template("browse_vendor.html", **config_args)

    else:
        data = {
            "vendor": vendor,
            "product": [
                x
                for x in app.dbh.connection.store_cves.distinct(
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
        "data": [
            {"vendors": x}
            for x in app.dbh.connection.store_cves.distinct("vendors")
            if x is not None
        ]
    }

    return retdata


def view_cve_id_name(*args, **kwargs):
    return [
        {
            "text": request.view_args["cve_id"],
            "url": "{}cve/{}".format(
                url_for("home.index"), request.view_args["cve_id"]
            ),
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
        return (
            render_template(
                "error.html",
                status={"except": "cve-not-found", "info": {"cve": cve_id}},
            ),
            404,
        )

    if app.config["WebInterface"]:
        cve = markCPEs(cve)

        return render_template("cve.html", cve=cve)
    else:
        return render_template("cve.html", cve=cve)


def view_cwe_id_name(*args, **kwargs):
    try:
        return [
            {"text": "CWE-List", "url": "{}cwe".format(url_for("home.index"))},
            {
                "text": "CWE-{}".format(request.view_args["cwe_id"]),
                "url": "{}cwe/{}".format(
                    url_for("home.index"), request.view_args["cwe_id"]
                ),
            },
        ]
    except KeyError:
        return [{"text": "CWE-List", "url": "{}cwe".format(url_for("home.index"))}]


@home.route("/cwe")
@home.route("/cwe/<cwe_id>")
@register_breadcrumb(home, ".cwe", "", dynamic_list_constructor=view_cwe_id_name)
def get_cwe(cwe_id=None):
    from lib.DatabaseLayer import (
        getCWEs,
        getCAPECFor,
    )

    data = getCWEs()
    if cwe_id is None:
        cwes = [x for x in data if x["weaknessabs"].lower() == "class"]
        return render_template("cwe.html", cwes=cwes, capec=None)
    else:
        cwes = {x["id"]: x["name"] for x in data}
        return render_template(
            "cwe.html", cwes=cwes, cwe=cwe_id, capec=getCAPECFor(cwe_id), minimal=True
        )


def view_capec_id_name(*args, **kwargs):
    return [
        {
            "text": "CAPEC-{}".format(request.view_args["capec_id"]),
            "url": "{}capec/{}".format(
                url_for("home.index"), request.view_args["capec_id"]
            ),
        }
    ]


@home.route("/capec/<capec_id>")
@register_breadcrumb(home, ".capec", "", dynamic_list_constructor=view_capec_id_name)
def capec(capec_id):
    from lib.DatabaseLayer import (
        getCWEs,
        getCAPEC,
    )

    data = getCWEs()
    cwes = {x["id"]: x["name"] for x in data}

    req_capec = getCAPEC(capec_id)
    if req_capec is None:
        return render_template(
            "error.html",
            status={"except": "capec-not-found", "info": {"capec": capec_id}},
        )

    rel_capecs = defaultdict(dict)

    if len(req_capec["related_capecs"]) != 0:
        for each in req_capec["related_capecs"]:
            rel_capecs[each] = getCAPEC(each)["summary"]

    return render_template(
        "capec.html", cwes=cwes, capecs=dict(rel_capecs), capec=req_capec
    )


def view_product_name(*args, **kwargs):
    vendor = request.view_args["vendor"]

    return [
        {
            "text": "{}".format(request.view_args["product"]),
            "url": "{}search/{}/{}".format(
                url_for("home.index"), vendor, request.view_args["product"]
            ),
        }
    ]


@home.route("/search/<vendor>/<path:product>")
@register_breadcrumb(
    home, ".browse.vendor", "", dynamic_list_constructor=view_product_name
)
def search(vendor=None, product=None):
    return render_template(
        "search.html", freetextsearch="", vendor=vendor, product=product, **config_args
    )


def view_freetext_search(*args, **kwargs):
    try:
        return [
            {
                "text": "Search: {}".format(request.view_args["freetextsearch"]),
                "url": "{}search/{}".format(
                    url_for("home.index"), request.view_args["freetextsearch"]
                ),
            }
        ]
    except KeyError:
        return [{"text": "Search", "url": ""}]


@home.route("/search/<freetextsearch>")
@register_breadcrumb(home, ".search", "", dynamic_list_constructor=view_freetext_search)
def freetext_search(freetextsearch=None):
    return render_template(
        "search.html",
        freetextsearch=freetextsearch,
        vendor="",
        product="",
        **config_args
    )


@home.route("/fetch_search_data", methods=["POST"])
def fetch_freetext_search():
    from lib.DatabaseLayer import (
        cvesForCPE,
        getSearchResults,
    )

    search = ""
    if request.values.get("search"):
        search = request.values.get("search")
    vendor = ""
    if request.values.get("vendor"):
        vendor = request.values.get("vendor")
    product = ""
    if request.values.get("product"):
        product = request.values.get("product")

    if search != "":
        result = getSearchResults(search)
        cve = {"data": result["data"], "total": len(result["data"])}
    elif vendor != "" and product != "":
        search = (vendor, product)
        result = cvesForCPE(search, strict_vendor_product=True)
        cve = {"data": result["results"], "total": len(result["results"])}
    else:
        return make_response(jsonify(False), 400)

    # errors = result["errors"] if "errors" in result else []
    return make_response(jsonify(cve), 200)


def view_linked(*args, **kwargs):
    key = request.view_args["key"]

    return [
        {
            "text": "{}".format(request.view_args["value"]),
            "url": "{}link/{}/{}".format(
                url_for("home.index"), key, request.view_args["value"]
            ),
        }
    ]


@home.route("/link/<key>/<value>")
@register_breadcrumb(home, ".linked", "", dynamic_list_constructor=view_linked)
def link(key=None, value=None):
    from lib.DatabaseLayer import (
        via4Linked,
    )

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
    try:
        filter_params = dict(request.json)
        if not current_user.is_authenticated:
            # Defaults matching the form defaults for an authenticated user.
            filter_params["blacklistSelect"] = "on"
            filter_params["whitelistSelect"] = "on"
            filter_params["unlistedSelect"] = "show"
        if validateFilter(filter_params):
            resp = make_response(jsonify(True), 200)
            resp.set_cookie("cve_filter", json.dumps(filter_params))
        else:
            resp = make_response(jsonify(False), 400)
    except TypeError:
        resp = make_response(jsonify(False), 400)
    return resp


@home.route("/reset_filter")
def reset_filter():
    resp = make_response(jsonify(defaultFilters), 200)
    resp.set_cookie("cve_filter", "", expires=0)
    return resp


@home.route("/filter_active")
def filter_active():
    try:
        filter_params = dict(json.loads(request.cookies.get("cve_filter")))
        if not validateFilter(filter_params):
            filter_params = defaultFilters
    except TypeError:
        filter_params = defaultFilters

    if filter_params == defaultFilters:
        resp = make_response(jsonify(False), 200)
        resp.set_cookie("cve_filter", "", expires=0)
    else:
        resp = make_response(jsonify(True), 200)
    return resp


@home.route("/get_filter")
def get_filter():
    try:
        filter_params = SanitizeUserInput(
            dict(json.loads(request.cookies.get("cve_filter")))
        )
        if not validateFilter(filter_params):
            filter_params = defaultFilters
    except TypeError:
        filter_params = defaultFilters
    return filter_params


@home.route("/fetch_cve_data", methods=["POST"])
def fetch_cvedata():
    try:
        filter_params = dict(json.loads(request.cookies.get("cve_filter")))
        if not validateFilter(filter_params):
            filter_params = defaultFilters
    except TypeError:
        filter_params = defaultFilters

    if filter_params == defaultFilters:
        ssd = ServerSideDataTable(request=request, backend=app.dbh.connection)
    else:
        query_filters = generate_full_query(filter_params)
        if len(query_filters) != 0:
            ssd = ServerSideDataTable(
                request=request,
                backend=app.dbh.connection,
                additional_filters=query_filters,
            )
        else:
            ssd = ServerSideDataTable(request=request, backend=app.dbh.connection)

    return_data = ssd.output_result()

    return return_data
