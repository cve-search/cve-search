import os
import threading
import subprocess
import sys

from flask import render_template, request, jsonify, url_for
from flask_breadcrumbs import default_breadcrumb_root, register_breadcrumb
from flask_login import current_user, login_required

from lib.Config import Configuration
from lib.DatabaseLayer import any_lock_active, colLOCKS
from web.home.utils import adminInfo
from . import admin
from ..run import app

config = Configuration()

default_breadcrumb_root(admin, ".Admin")


@admin.route("/")
@register_breadcrumb(admin, ".", "Admin")
@login_required
def admin_home():
    feeds = {
        "cpe": config.includesFeed("cpe"),
        "cve": config.includesFeed("cve"),
        "cwe": config.includesFeed("cwe"),
        "capec": config.includesFeed("capec"),
        "via4": config.includesFeed("via4"),
        "epss": config.includesFeed("epss"),
    }
    show_pwd_form = config.loginRequired() and not config.useOIDC()
    return render_template(
        "admin.html",
        status="default",
        feeds=feeds,
        **adminInfo(),
        show_pwd_form=show_pwd_form,
    )


@admin.route("/change_pass", methods=["GET", "POST"])
@login_required
def change_pass():
    post_data = dict(request.json)

    current_pass = post_data["current_pass"]
    new_pass = post_data["new_pass"]
    if current_user.authenticate(current_pass):
        if new_pass:
            app.dbh.connection.changePassword(current_user.id, new_pass)
            return jsonify({"status": "password_changed"})
        return jsonify({"status": "no_password"})
    else:
        return jsonify({"status": "wrong_user_pass"})


@admin.route("/updatedb")
@login_required
def updatedb():
    if any_lock_active():
        return (
            jsonify(
                {"status": "locked", "message": "Another update is already running."}
            ),
            409,
        )

    args = [
        sys.executable,
        os.path.join(app.config["run_path"], "../sbin/db_updater.py"),
    ]

    flags = {"cache": "-c"}
    for arg, flag in flags.items():
        if request.args.get(arg, "false").lower() == "true":
            args.append(flag)

    VALID_SOURCES = {"cpe", "cve", "cwe", "capec", "via4", "epss"}
    sources = request.args.getlist("sources")
    filtered_sources = [s for s in sources if s in VALID_SOURCES]

    if filtered_sources:
        args.append("-s")
        args.extend(filtered_sources)

    # Spawn the child in a daemon thread to reap it properly
    def run_updater(args):
        proc = subprocess.Popen(args, stdout=sys.stdout, stderr=sys.stderr)
        proc.wait()  # ensures the child is reaped when finished

    threading.Thread(target=run_updater, args=(args,), daemon=True).start()

    return jsonify({"status": "db_updated"})


@admin.route("/clear_updater_locks", methods=["POST"])
@login_required
def clear_updater_locks():
    locks = list(colLOCKS.find({}, {"_id": 1}))
    removed_locks = [lock["_id"] for lock in locks]
    colLOCKS.delete_many({})

    return jsonify(
        {
            "status": "success",
            "removed_locks": removed_locks,
            "message": f"Cleared {len(removed_locks)} updater locks.",
        }
    )


def view_WorB(*args, **kwargs):
    worb = request.url_rule.rule.split("/")[-1]
    return [
        {"text": worb.title(), "url": "{}{}".format(url_for("admin.admin_home"), worb)}
    ]
