from flask import redirect, request, render_template, url_for
from flask_login import logout_user, login_required, login_user, current_user

from lib.Authentication import AuthenticationHandler
from lib.Config import Configuration
from lib.User import User
from . import auth
from .forms import LoginForm
from ..home.utils import defaultFilters

config = Configuration()
auth_handler = AuthenticationHandler()


@auth.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("home.index"))

    form = LoginForm()

    if not config.loginRequired():
        person = User.get("_dummy_", auth_handler)
        defaultFilters.update(
            {
                "blacklistSelect": "on",
                "whitelistSelect": "on",
                "unlistedSelect": "show",
            }
        )
        login_user(person)

        return redirect(url_for("admin.admin_home"))

    if form.validate_on_submit():

        # validate username and password
        username = request.form.get("username")
        password = request.form.get("password")
        person = User.get(username, auth_handler)
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
            return render_template("login.html", form=form, status="wrong_user_pass")
    else:
        return render_template("login.html", form=form)


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
    logout_user()
    return redirect("/")
