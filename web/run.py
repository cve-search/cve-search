import logging
import random
import urllib
from datetime import timedelta

from CveXplore import CveXplore
from CveXplore.errors.database import DatabaseSchemaVersionError

from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap
from flask_breadcrumbs import Breadcrumbs
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_plugins import PluginManager, get_enabled_plugins
from oauthlib.oauth2 import WebApplicationClient

from lib.Config import Configuration
from lib.LogHandler import AppLogger
from lib.Toolkit import isURL
from lib.User import User
from web.helpers.flask_authentication import FlaskAuthHandler
from web.helpers.flask_database import FlaskDatabaseHandler

login_manager = LoginManager()
auth_handler = FlaskAuthHandler()
plugins = PluginManager()
dbh = FlaskDatabaseHandler()

config = Configuration()

cvex = CveXplore(mongodb_connection_details={"host": config.getMongoUri()})

app = None
token_blacklist = None
oidcClient = None

ACCESS_EXPIRES = timedelta(minutes=15)
REFRESH_EXPIRES = timedelta(days=30)

logging.setLoggerClass(AppLogger)


def create_app(version, run_path):
    global app, token_blacklist, oidcClient, config

    app = Flask(__name__)

    app.config["version"] = version
    app.config["run_path"] = run_path

    if config.getWebInterface().lower() == "full":
        app.config["WebInterface"] = False
    else:
        app.config["WebInterface"] = True

    app.config["MONGO_DBNAME"] = config.getMongoDB()
    app.config["SECRET_KEY"] = str(random.getrandbits(256))
    app.config["JWT_SECRET_KEY"] = str(random.getrandbits(256))

    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = REFRESH_EXPIRES
    app.config["JWT_BLACKLIST_ENABLED"] = True
    app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]

    token_blacklist = config.getRedisTokenConnection()

    app.config["RESTX_MASK_SWAGGER"] = False
    app.config["SWAGGER_UI_DOC_EXPANSION"] = "list"

    Breadcrumbs(app=app)
    Bootstrap(app)
    jwt = JWTManager(app)
    plugins.init_app(app)
    dbh.init_app(app)
    auth_handler.init_app(app)

    @jwt.additional_claims_loader
    def add_claims_to_access_token(identity):
        return {"user": identity}

    @jwt.token_in_blocklist_loader
    def check_if_token_is_revoked(decrypted_token):
        jti = decrypted_token["jti"]
        entry = token_blacklist.get(jti)
        if entry == "true":
            return True
        return False

    login_manager.init_app(app)
    login_manager.login_message = "You must be logged in to access this page!!!"
    login_manager.login_view = "auth.login"

    # CORS
    @app.after_request
    def apply_caching(response):
        reqURL = request.base_url
        if (
            config.getCORS()
            and reqURL.count("/api/") == 1
            and reqURL.count("/admin") == 0
        ):
            response.headers.add(
                "Access-Control-Allow-Origin", config.getCORSAllowOrigin()
            )
        return response

    # OAuth 2 client setup
    if config.useOIDC():
        oidcClient = WebApplicationClient(config.getClientID())

    @login_manager.user_loader
    def load_user(id):
        return User.get(id, auth_handler)

    from .home import home as home_blueprint

    app.register_blueprint(home_blueprint)

    if not app.config["WebInterface"]:
        from .auth import auth as auth_blueprint

        app.register_blueprint(auth_blueprint)

        from .admin import admin as admin_blueprint

        app.register_blueprint(admin_blueprint, url_prefix="/admin")

    from .restapi import blueprint as api

    app.register_blueprint(api)

    @app.context_processor
    def version():
        def get_version():
            return app.config["version"]

        return dict(get_version=get_version)

    @app.context_processor
    def get_active_plugins():
        def get_active_plugins():
            all = list(get_enabled_plugins())
            if len(all) != 0:
                return True
            return False

        return dict(get_active_plugins=get_active_plugins)

    @app.context_processor
    def db_schema():
        def db_schema():
            try:
                return cvex.database.validate_schema()
            except DatabaseSchemaVersionError as err:
                return err

        return dict(db_schema=db_schema)

    @app.context_processor
    def WebInterface():
        def get_WebInterface():
            return app.config["WebInterface"]

        return dict(get_WebInterface=get_WebInterface)

    @app.context_processor
    def JSON2HTMLTable():
        # Doublequote, because we have to |safe the content for the tags
        def doublequote(data):
            return urllib.parse.quote_plus(urllib.parse.quote_plus(data))

        def JSON2HTMLTableFilter(data, stack=None):
            _return = ""
            if type(stack) == str:
                stack = [stack]

            if type(data) == list:
                if len(data) == 1:
                    _return += JSON2HTMLTableFilter(data[0], stack)
                else:
                    _return += '<ul class="via4">'
                    for item in data:
                        _return += "<li>%s</li>" % JSON2HTMLTableFilter(item, stack)
                    _return += "</ul>"
            elif type(data) == dict:
                _return += '<table class="invisiTable">'
                for key, val in sorted(data.items()):
                    _return += "<tr><td><b>%s</b></td><td>%s</td></tr>" % (
                        key,
                        JSON2HTMLTableFilter(val, stack + [key]),
                    )
                _return += "</table>"
            elif type(data) == str:
                if stack:
                    _return += (
                        "<a href='/link/"
                        + doublequote(".".join(stack))
                        + "/"
                        + doublequote(data)
                        + "'>"
                    )  # link opening
                    _return += "<i class='fas fa-link' aria-hidden='true'></i> </a>"
                _return += (
                    "<a target='_blank' href='%s'>%s</a>" % (data, data)
                    if isURL(data)
                    else data
                )
            _return += ""
            return _return

        return dict(JSON2HTMLTable=JSON2HTMLTableFilter)

    @app.template_filter("htmlEncode")
    def htmlEncode(string):
        return urllib.parse.quote_plus(string).lower()

    @app.template_filter("htmlDecode")
    def htmlDecode(string):
        return urllib.parse.unquote_plus(string)

    @app.template_filter("sortIntLikeStr")
    def sortIntLikeStr(datalist):
        return sorted(datalist, key=lambda k: int(k))

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template("404.html"), 404

    return app
