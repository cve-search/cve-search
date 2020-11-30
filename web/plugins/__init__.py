from flask import Blueprint

plugins = Blueprint("plugins", __name__)

from . import views
