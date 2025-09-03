from flask import Blueprint
from flask_restx import Api

from web.run import app
from .browse_vendor import api as browse_api
from .capec import api as capec_api
from .cpe_convert import api as cpe_api
from .cve import api as cve_api
from .cwe import api as cwe_api
from .dbinfo import api as dbinfo_api
from .query import api as query_api
from .search_vendor import api as search_vendor_api

namespaces = [
    cpe_api,
    cve_api,
    cwe_api,
    capec_api,
    query_api,
    browse_api,
    search_vendor_api,
    dbinfo_api,
]

blueprint = Blueprint("api", __name__, url_prefix="/api")

api = Api(
    blueprint,
    title="CVE-Search",
    version=app.config["version"],
    description="CVE-Search API documentation",
)

for each in namespaces:
    api.add_namespace(each)
