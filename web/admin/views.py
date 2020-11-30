import os
import re
import subprocess
import sys
import urllib
from io import BytesIO

from flask import render_template, request, jsonify, send_file
from flask_breadcrumbs import default_breadcrumb_root, register_breadcrumb
from flask_login import current_user, login_required
from redis import exceptions as redisExceptions

from lib.Config import Configuration
from lib.DatabaseHandler import DatabaseHandler
from lib.DatabaseLayer import (
    getWhitelist,
    getBlacklist,
    getCVEs,
)
from lib.Query import getVersionsOfProduct
from sbin.db_blacklist import (
    countBlacklist,
    dropBlacklist,
    importBlacklist,
    exportBlacklist,
    removeBlacklist,
    updateBlacklist,
)
from sbin.db_whitelist import (
    countWhitelist,
    dropWhitelist,
    importWhitelist,
    exportWhitelist,
    removeWhitelist,
    updateWhitelist,
)
from web.home.utils import adminInfo, addCPEToList
from . import admin
from ..run import app

config = Configuration()

dbh = DatabaseHandler()

default_breadcrumb_root(admin, ".Admin")


@admin.route("/")
@register_breadcrumb(admin, ".", "Admin")
@login_required
def admin_home():

    return render_template("admin.html", status="default", **adminInfo())


@admin.route("/change_pass", methods=["GET", "POST"])
@login_required
def change_pass():

    post_data = dict(request.json)

    current_pass = post_data["current_pass"]
    new_pass = post_data["new_pass"]
    if current_user.authenticate(current_pass):
        if new_pass:
            dbh.connection.changePassword(current_user.id, new_pass)
            return jsonify({"status": "password_changed"})
        return jsonify({"status": "no_password"})
    else:
        return jsonify({"status": "wrong_user_pass"})


@admin.route("/updatedb")
@login_required
def updatedb():
    subprocess.Popen(
        [
            sys.executable,
            os.path.join(app.config["run_path"], "../sbin/db_updater.py"),
            "-civ",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    return jsonify({"status": "db_updated"})


def view_WorB(*args, **kwargs):

    return [
        {
            "text": request.url_rule.rule.split("/")[2].title(),
            "url": request.url_rule.rule,
        }
    ]


@admin.route("/whitelist")
@admin.route("/blacklist")
@register_breadcrumb(admin, ".W-B_list", "", dynamic_list_constructor=view_WorB)
@login_required
def listView():
    if request.url_rule.rule.split("/")[2].lower() == "whitelist":
        return render_template("list.html", rules=getWhitelist(), listType="Whitelist")
    else:
        return render_template("list.html", rules=getBlacklist(), listType="Blacklist")


@admin.route("/whitelist/import", methods=["GET", "POST"])
@admin.route("/blacklist/import", methods=["GET", "POST"])
@login_required
def listImport():
    _list = request.url_rule.rule.split("/")[2]
    file = request.files["file"]
    force = request.form.get("force")
    count = countWhitelist() if _list.lower() == "whitelist" else countBlacklist()
    if (count == 0) | (not count) | (force == "f"):
        if _list.lower() == "whitelist":
            dropWhitelist()
            importWhitelist(file.stream)
        else:
            dropBlacklist()
            importBlacklist(file.stream)
        status = _list[0] + "l_imported"
    else:
        status = _list[0] + "l_already_filled"
    return render_template("admin.html", status=status, **adminInfo())


@admin.route("/whitelist/export")
@admin.route("/blacklist/export")
@login_required
def listExport():
    _list = request.url_rule.rule.split("/")[2]
    if _list.lower() == "whitelist":
        data = exportWhitelist()
    else:
        data = exportBlacklist()
    bytIO = BytesIO()
    bytIO.write(bytes(data, "utf-8"))
    bytIO.seek(0)
    return send_file(bytIO, as_attachment=True, attachment_filename=_list + ".txt")


@admin.route("/whitelist/drop")
@admin.route("/blacklist/drop")
@login_required
def listDrop():
    _list = request.url_rule.rule.split("/")[2].lower()
    if _list == "whitelist":
        dropWhitelist()
    else:
        dropBlacklist()
    return jsonify({"status": _list[0] + "l_dropped"})


@admin.route("/addToList")
@login_required
def listAdd():
    cpe = request.args.get("cpe")
    cpeType = request.args.get("type")
    lst = request.args.get("list")
    if cpe and cpeType and lst:
        status = (
            "added_to_list"
            if addCPEToList(cpe, lst, cpeType)
            else "already_exists_in_list"
        )
        returnList = getWhitelist() if lst.lower() == "whitelist" else getBlacklist()
        return jsonify({"status": status, "rules": returnList, "listType": lst.title()})
    else:
        return jsonify({"status": "could_not_add_to_list"})


@admin.route("/removeFromList")
@login_required
def listRemove():
    cpe = request.args.get("cpe", type=str)
    cpe = urllib.parse.quote_plus(cpe).lower()
    cpe = cpe.replace("%3a", ":")
    cpe = cpe.replace("%2f", "/")
    cpe = cpe.replace("%2a", "*")
    lst = request.args.get("list", type=str)
    if cpe and lst:
        result = (
            removeWhitelist(cpe) if lst.lower() == "whitelist" else removeBlacklist(cpe)
        )
        status = "removed_from_list" if (result > 0) else "already_removed_from_list"
    else:
        status = "invalid_cpe"
    returnList = getWhitelist() if lst.lower() == "whitelist" else getBlacklist()
    return jsonify({"status": status, "rules": returnList, "listType": lst.title()})


@admin.route("/editInList")
@login_required
def listEdit():
    old = request.args.get("oldCPE")
    new = request.args.get("cpe")
    lst = request.args.get("list")
    CPEType = request.args.get("type")
    if old and new:
        result = (
            updateWhitelist(old, new, CPEType)
            if lst == "whitelist"
            else updateBlacklist(old, new, CPEType)
        )
        status = "cpelist_updated" if (result) else "cpelist_update_failed"
    else:
        status = "invalid_cpe"
    returnList = (
        list(getWhitelist()) if lst.lower() == "whitelist" else list(getBlacklist())
    )
    return jsonify({"rules": returnList, "status": status, "listType": lst})


def view_listmanagement(*args, **kwargs):

    try:
        product = request.view_args["product"]
    except KeyError:
        product = None

    try:
        if product is None:
            return [
                {"text": "List-Management", "url": "/admin/listmanagement",},
                {
                    "text": "{}".format(request.view_args["vendor"]),
                    "url": "/admin/listmanagement/{}".format(
                        request.view_args["vendor"]
                    ),
                },
            ]
        else:
            return [
                {"text": "List-Management", "url": "/admin/listmanagement",},
                {
                    "text": "{}".format(request.view_args["vendor"]),
                    "url": "/admin/listmanagement/{}".format(
                        request.view_args["vendor"]
                    ),
                },
                {
                    "text": "{}".format(request.view_args["product"]),
                    "url": "/admin/listmanagement/{}/{}".format(
                        request.view_args["vendor"], request.view_args["product"]
                    ),
                },
            ]
    except KeyError:
        return [{"text": "List-Management", "url": "/admin/listmanagement",}]


@admin.route("/listmanagement")
@admin.route("/listmanagement/<vendor>")
@admin.route("/listmanagement/<vendor>/<product>")
@register_breadcrumb(
    admin, ".listmanagement_spec", "", dynamic_list_constructor=view_listmanagement
)
@login_required
def listManagement(vendor=None, product=None):
    try:
        if product is None and vendor is None:
            # no product selected yet, so same function as /browse can be used
            vendor = [x for x in dbh.connection.store_cves.distinct("vendors") if x is not None]
            product = None
            version = None
        elif product is None:
            vendor = vendor
            product = [x for x in dbh.connection.store_cves.distinct("products", {"vendors": vendor}) if x is not None]
            version = None
        else:
            # product selected, product versions required
            version = getVersionsOfProduct(urllib.parse.quote_plus(product).lower())
        return render_template(
            "listmanagement.html", vendor=vendor, product=product, version=version
        )
    except redisExceptions.ConnectionError:
        return render_template(
            "error.html",
            status={
                "except": "redis-connection",
                "info": {"host": config.getRedisHost(), "port": config.getRedisPort(),},
            },
        )


@admin.route("/listmanagement/add", methods=["GET", "POST"])
@login_required
def listManagementAdd():

    # this functionality is broken; needs further investigation....

    post_data = dict(request.json)

    redisdb = config.getRedisVendorConnection()
    # retrieve the separate item parts
    item = post_data["item"]
    listType = post_data["list"]

    pattern = re.compile("^[a-z:/0-9.~_%-]+$")

    if pattern.match(item):
        item = item.split(":")
        added = False
        if len(item) == 1:
            # only vendor, so a check on cpe type is needed
            if redisdb.sismember("t:/o", item[0]):
                if addCPEToList("cpe:/o:" + item[0], listType):
                    added = True
            if redisdb.sismember("t:/a", item[0]):
                if addCPEToList("cpe:/a:" + item[0], listType):
                    added = True
            if redisdb.sismember("t:/h", item[0]):
                if addCPEToList("cpe:/h:" + item[0], listType):
                    added = True
        elif 4 > len(item) > 1:
            # cpe type can be found with a mongo regex query
            result = getCVEs(query={"cpe_2_2": {"$regex": item[1]}})["results"]
            if len(result) != 0:
                prefix = ((result[0])["cpe_2_2"])[:7]
                if len(item) == 2:
                    if addCPEToList(prefix + item[0] + ":" + item[1], listType):
                        added = True
                if len(item) == 3:
                    if addCPEToList(
                        prefix + item[0] + ":" + item[1] + ":" + item[2], listType
                    ):
                        added = True
        status = "added_to_list" if added else "could_not_add_to_list"
    else:
        status = "invalid_cpe"
    j = {"status": status, "listType": listType}
    return jsonify(j)
