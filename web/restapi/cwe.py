from flask_restx import Namespace, Resource, fields

from lib.DatabaseLayer import getCWEs
from web.restapi.cpe_convert import message

api = Namespace("cwe", description="Endpoints for requesting cwe information", path="/")

cwe = api.model(
    "Cwe",
    {
        "name": fields.String(
            description="Name of the CWE", example="Incorrect Selection of Fuse Values"
        ),
        "id": fields.String(description="ID of the CWE", example="1253"),
        "status": fields.String(description="Status of the CWE", example="Draft"),
        "weaknessabs": fields.String(description="Category of the CWE", example="Base"),
        "Description": fields.String(
            description="Description of the CWE",
            example="Logic should be designed in a way that blown fuses do not put the product into an insecure state "
            "that can be leveraged by an attacker. Logic should be designed in a way that blown fuses do not "
            "put the product into an insecure state that can be leveraged by an attacker. ",
        ),
        "related_weaknesses": fields.List(
            fields.String,
            description="List of related weaknesses of the CWE",
            example=["693"],
        ),
    },
)


@api.route("/cwe")
@api.response(400, "Error processing request", model=message)
@api.response(404, "The requested CWE is not found", model=message)
@api.response(500, "Server error", model=message)
class CweId(Resource):
    @api.marshal_list_with(cwe, skip_none=True)
    def get(self):
        """
        List all CWE's

        Outputs a list of all CWEs (Common Weakness Enumeration).
        """
        cwes = getCWEs()

        if cwes is None:
            api.abort(404, "The requested CWE is not found")
        else:
            return cwes


@api.route("/cwe/<cwe_id>")
@api.param("cwe_id", "CWE id", example="1253")
@api.response(400, "Error processing request", model=message)
@api.response(404, "The requested CWE is not found", model=message)
@api.response(500, "Server error", model=message)
class CweId(Resource):
    @api.marshal_with(cwe, skip_none=True)
    def get(self, cwe_id):
        """
        CWE from CWE ID

        Outputs a specific CWE (Common Weakness Enumeration).
        """
        cwes = getCWEs(cwe_id)

        if cwes is None:
            api.abort(404, "The requested CWE is not found")
        else:
            return cwes
