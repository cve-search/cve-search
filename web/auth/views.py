import json
import logging
import urllib.parse

import requests
from flask import redirect, request, render_template, url_for
from flask_login import logout_user, login_required, login_user, current_user
from requests.adapters import HTTPAdapter
from urllib3 import Retry

from lib.LogHandler import AppLogger
from lib.User import User
from . import auth
from .forms import LoginForm
from ..home.utils import defaultFilters
from ..run import oidcClient, config, app

logging.setLoggerClass(AppLogger)

logger = logging.getLogger(__name__)


def get_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(429, 500, 502, 503, 504),
    session=None,
):
    """
    Method for returning a session object
    """
    # disabling annoying messages from urllib3
    requests.packages.urllib3.disable_warnings()

    proxies = {"http": config.getProxy(), "https": config.getProxy()}

    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )

    session.proxies.update(proxies)

    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def get_idp_provider_cfg():
    with get_session() as session:
        data = session.get(
            config.getIDPDiscoveryUrl(), verify=config.useSSLVerify()
        ).json()

    return data


@auth.route("/oidc-login/callback", methods=["GET"])
def callback():
    # Get authorization code IDP sent back
    form = LoginForm()
    try:
        code = request.args.get("code")
        idp_provider_cfg = get_idp_provider_cfg()
        token_endpoint = idp_provider_cfg["token_endpoint"]
        # Request to get tokens from IDP
        token_url, headers, body = oidcClient.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=request.base_url,
            code=code,
        )
        with get_session() as session:
            token_response = session.post(
                token_url,
                headers=headers,
                data=body,
                auth=(config.getClientID(), config.getClientSecret()),
                verify=config.useSSLVerify(),
            )

        # Parse the tokens!
        oidcClient.parse_request_body_response(json.dumps(token_response.json()))
        # find and hit the userinfo endpoint
        # from IDP that gives user's profile information,
        # including their preferred username -
        userinfo_endpoint = idp_provider_cfg["userinfo_endpoint"]
        uri, headers, body = oidcClient.add_token(userinfo_endpoint)

        with get_session() as session:
            userinfo_response = session.get(
                uri, headers=headers, data=body, verify=config.useSSLVerify()
            )

        # Login the user
        preferred_username = userinfo_response.json()["preferred_username"]
        if preferred_username:
            person = User.get(preferred_username, app.auth_handler)
            defaultFilters.update(
                {
                    "blacklistSelect": "on",
                    "whitelistSelect": "on",
                    "unlistedSelect": "show",
                }
            )
            login_user(person)
            return redirect(url_for("admin.admin_home"))
        else:
            return render_template(
                "login.html", form=form, status="auth_again", show_oidc=config.useOIDC()
            )
    except Exception as err:
        logger.error(f"****OIDC callback exception***** --> {err}")
        return render_template(
            "login.html", form=form, status="auth_again", show_oidc=config.useOIDC()
        )


@auth.route("/oidc-login", methods=["GET"])
def oidcLogin():
    # display OIDC only when in conf
    if config.useOIDC():
        # Find out what URL to hit for IDP login
        idp_provider_cfg = get_idp_provider_cfg()
        authorization_endpoint = idp_provider_cfg["authorization_endpoint"]

        # construct the request for IDP login and provide
        # scopes to retrieve user's profile from IDP
        request_uri = oidcClient.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=request.base_url + "/callback",
            scope=["openid", "email", "profile"],
        )
        return request_uri


@auth.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if current_user.is_authenticated:
        return redirect(url_for("home.index"))

    if not config.loginRequired():
        person = User.get("_dummy_", app.auth_handler)
        defaultFilters.update(
            {"blacklistSelect": "on", "whitelistSelect": "on", "unlistedSelect": "show"}
        )
        login_user(person)

        return redirect(url_for("admin.admin_home"))

    if form.validate_on_submit():
        # validate username and password
        username = request.form.get("username")
        password = request.form.get("password")
        person = User.get(username, app.auth_handler)
        if person and person.authenticate(password):
            defaultFilters.update(
                {
                    "blacklistSelect": "on",
                    "whitelistSelect": "on",
                    "unlistedSelect": "show",
                }
            )
            login_user(person)
            return redirect(url_for("admin.admin_home"))
        else:
            return render_template(
                "login.html",
                form=form,
                status="wrong_user_pass",
                show_oidc=config.useOIDC(),
            )
    else:
        return render_template("login.html", form=form, show_oidc=config.useOIDC())


# @auth.route("/register", methods=["GET", "POST"])
# def register():
#
#     form = RegistrationForm()
#     if form.validate_on_submit():
#
#         pass
#
#     else:
#         return render_template("register.html", form=form)


@auth.route("/logout")
@login_required
def logout():
    redirect_url = "/"
    logout_user()
    if config.useOIDC():
        idp_provider_cfg = get_idp_provider_cfg()
        end_session_endpoint = idp_provider_cfg["end_session_endpoint"]
        redirect_url = "{end_session_endpoint}?redirect_uri={redirect_uri}".format(
            end_session_endpoint=end_session_endpoint,
            redirect_uri=urllib.parse.quote(request.base_url, safe="/:?&="),
        )
    return redirect(urllib.parse.quote(redirect_url, safe="/:?&="))
