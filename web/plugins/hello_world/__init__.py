from flask import Blueprint, render_template, render_template_string
from flask_plugins import connect_event

from web.helpers.app_plugin import AppPlugin

__plugin__ = "HelloWorld"
__version__ = "1.0.0"


def inject_navigation_link():
    return render_template_string(
        """
            <a class="nav-item nav-link" href="{{ url_for('hello.index') }}">Hello World</a>
        """
    )


def inject_dropdown_navigation_link():
    return render_template_string(
        """
            <a class="dropdown-item" href="{{ url_for('hello.index') }}">Hello World</a>
        """
    )


def inject_tab_header():
    return render_template_string(
        """
        <ul class="nav nav-pills">
          <li class="nav-item"><a class="nav-link active" href="#hello" data-toggle="tab">Hello World</a></li>
        </ul>
        """
    )


def inject_tab_content():
    return render_template_string(
        """
        <div class="tab-content">
          <div class="active tab-pane" id="hello">
            <div class="card">
                <div class="card-body">
                  Hello world in tab
                </div>
            </div>
          </div>
        </div>
        """
    )


hello = Blueprint("hello", __name__, template_folder="templates")


@hello.route("/")
def index():
    return render_template("hello.html")


class HelloWorld(AppPlugin):
    def setup(self):
        self.register_blueprint(hello, url_prefix="/hello")

        connect_event("footer_tab_header", inject_tab_header)
        connect_event("footer_tab_content", inject_tab_content)

        connect_event("tmpl_navigation_last", inject_navigation_link)
        connect_event("tmpl_navigation_dropdown", inject_dropdown_navigation_link)
