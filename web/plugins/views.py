import jinja2
from flask import request, jsonify, render_template, abort
from flask_login import current_user

from . import plugins
from ..home.utils import get_cve_actions, plugManager, pluginArgs


@plugins.route("/_get_cve_actions")
def fetch_cve_actions():
    cve = request.args.get("cve", type=str)
    actions = get_cve_actions(cve)
    return jsonify({"actions": actions})


@plugins.route("/<plugin>")
def openPlugin(plugin):
    if (
            plugManager.requiresAuth(plugin)
            and not current_user.is_authenticated
    ):
        return render_template("requiresAuth.html")
    else:
        page, args = plugManager.openPage(plugin, **pluginArgs)
        if page:
            try:
                return render_template(page, **args)
            except jinja2.exceptions.TemplateSyntaxError:
                return render_template(
                    "error.html", status={"except": "plugin-page-corrupt"}
                )
            except jinja2.exceptions.TemplateNotFound:
                return render_template(
                    "error.html",
                    status={"except": "plugin-page-not-found", "page": page},
                )
        else:
            abort(404)


@plugins.route("/<plugin>/subpage/<page>")
def openPluginSubpage(plugin, page):
    if (
            plugManager.requiresAuth(plugin)
            and not current_user.is_authenticated
    ):
        return render_template("requiresAuth.html")
    else:
        page, args = plugManager.openSubpage(plugin, page, **pluginArgs)
        if page:
            try:
                return render_template(page, **args)
            except jinja2.exceptions.TemplateSyntaxError:
                return render_template(
                    "error.html", status={"except": "plugin-page-corrupt"}
                )
            except jinja2.exceptions.TemplateNotFound:
                return render_template(
                    "error.html",
                    status={"except": "plugin-page-not-found", "page": page},
                )
        else:
            abort(404)


@plugins.route("/<plugin>/_cve_action/<action>")
def _jsonCVEAction(plugin, action):
    cve = request.args.get("cve", type=str)
    response = plugManager.onCVEAction(
        cve, plugin, action, fields=dict(request.args), **pluginArgs
    )
    if type(response) is bool and response is True:
        return jsonify({"status": "plugin_action_complete"})
    elif type(response) is bool and response is False or response is None:
        return jsonify({"status": "plugin_action_failed"})
    elif type(response) is dict:
        return jsonify(response)
