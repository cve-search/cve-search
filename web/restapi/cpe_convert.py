from flask_restx import Namespace, Resource, fields

from lib.Toolkit import toOldCPE, toStringFormattedCPE

api = Namespace(
    "cpe",
    description="Endpoints for cpe conversion between different versions",
    path="/",
)

message = api.model(
    "Message",
    {
        "message": fields.String(
            description="The response message",
            example="The messages indicating the cause or reason for failure or success.",
        )
    },
)


@api.route("/cpe2.2/<path:cpe>")
@api.param(
    "cpe",
    "CPE code in cpe2.3 format",
    example="cpe:2.3:o:microsoft:windows_vista:6.0:sp1:-:-:home_premium:-:-:x64:-",
    required=True,
)
@api.response(
    200,
    "CPE converted",
    model=fields.String(
        description="CPE code converted to 2.2 format",
        example="cpe:/o:microsoft:windows_vista:6.0:sp1:~~home_premium~~x64~",
    ),
)
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class Cpe3To2(Resource):
    def get(self, cpe):
        """
        convert 3 to 2

        Converts a CPE code to the CPE2.2 standard, stripped of appendices.
        CPE2.2 is the old standard, and is a lot less uniform than the CPE2.3 standard.
        """
        cpe = toOldCPE(cpe)
        if cpe is False:
            return api.abort(
                400, "Conversion failed, the CPE code you provided cannot be converted"
            )
        else:
            return cpe


@api.route("/cpe2.3/<path:cpe>")
@api.param(
    "cpe",
    "CPE code in cpe2.2 format",
    example="cpe:/o:microsoft:windows_vista:6.0:sp1:~-~home_premium~-~x64~-",
    required=True,
)
@api.response(
    200,
    "CPE converted",
    model=fields.String(
        description="CPE code converted to 2.3 format",
        example="cpe:2.3:o:microsoft:windows_vista:6.0:sp1:-:-:home_premium:-:-:x64",
    ),
)
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class Cpe2To3(Resource):
    def get(self, cpe):
        """
        convert 2 to 3

        Converts a CPE code to the CPE2.3 standard, stripped of appendices.
        CPE2.3 is the newer standard, and is a lot more uniform and easier to read than the CPE2.2 standard.
        """
        cpe = toStringFormattedCPE(cpe)
        if cpe is False:
            return api.abort(
                400, "Conversion failed, the CPE code you provided cannot be converted"
            )
        else:
            return cpe
