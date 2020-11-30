from flask_restx import Namespace, Resource, fields

from lib.DatabaseLayer import getCAPEC, getCAPECFor
from web.restapi.cpe_convert import message
from web.restapi.cve import capec_entry

api = Namespace(
    "capec", description="Endpoints for requesting capec information", path="/"
)


@api.route("/capec/show/<capec_id>")
@api.param("capec_id", "CAPEC id", example="112")
@api.response(400, "Error processing request", model=message)
@api.response(404, "The requested CAPEC is not found", model=message)
@api.response(500, "Server error", model=message)
class CapecId(Resource):
    @api.marshal_with(capec_entry)
    def get(self, capec_id):
        """
        CAPEC from CAPEC ID

        Outputs a CAPEC specified by it's id.
        CAPEC (Common Attack Pattern Enumeration and Classification) are a list of attack types commonly used by attackers.
        """
        capec = getCAPEC(capec_id)

        if capec is None:
            api.abort(404, "The requested CAPEC is not found")
        else:
            return capec


@api.route("/capec/<cwe_id>")
@api.param("cwe_id", "CWE id", example="1253")
@api.response(400, "Error processing request", model=message)
@api.response(404, "The requested CAPEC is not found", model=message)
@api.response(500, "Server error", model=message)
class CapecByCweId(Resource):
    @api.marshal_list_with(capec_entry)
    def get(self, cwe_id):
        """
        CAPEC's from CWE ID

        Outputs a list of CAPEC related to a CWE.
        CAPEC (Common Attack Pattern Enumeration and Classification) are a list of attack types commonly used by attackers.
        """
        capecs = getCAPECFor(cwe_id)

        if len(capecs) == 0:
            api.abort(404, "The requested CAPEC is not found")
        else:
            return capecs
