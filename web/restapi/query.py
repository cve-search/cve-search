import json

from bson import json_util
from dicttoxml import dicttoxml
from flask import request, Response
from flask_restx import Namespace, fields, Resource

from lib.ApiRequests import JSONApiRequest
from lib.DatabaseHandler import DatabaseHandler
from web.home.utils import filter_logic, parse_headers
from web.restapi.cpe_convert import message
from web.restapi.cve import cve_last_entries

api = Namespace(
    "query", description="Endpoints for querying the cve search database", path="/"
)


query_entries = api.model(
    "QueryEntries",
    {
        "results": fields.List(
            fields.Nested(cve_last_entries),
            description="Results from query",
        ),
        "total": fields.Integer(
            description="Total amount of records available for this query",
            example="1337",
        ),
    },
)

PostBodyRequest = api.model(
    "ApiPostRequest",
    {
        "retrieve": fields.String(
            description="Retrieve data from this collection, allowed options are 'capec', 'cpe', 'cves', 'cwe', 'via4'",
            example="cves",
            required=True,
        ),
        "dict_filter": fields.Raw(
            description="filter according to pymongo docs",
            example={
                "vulnerable_configuration": "cpe:2.3:o:totolink:t10_firmware:4.1.8cu.5803_b20200521:*:*:*:*:*:*:*"
            },
            required=True,
        ),
        "limit": fields.Integer(
            description="Limit the amount of returned documents", example=10
        ),
        "skip": fields.Integer(
            description="Skip the first N amount of documents", example=0
        ),
        "sort": fields.String(description="Sort on this field", example="cvss"),
        "sort_dir": fields.String(
            description="sorting direction ASC = pymongo.ASCENDING, DESC = pymongo.DESCENDING",
            example="ASC",
        ),
        "query_filter": fields.Raw(
            description="query filter to exclude certain fields (via a 0) or to limit query to a specific set (via a 1)",
            example={"access": 0, "cwe": 0},
        ),
    },
)

PostBodyResponse = api.model(
    "ApiPostResponse",
    {
        "data": fields.List(
            fields.Raw,
            description="Returned data",
            example=[
                {
                    "_id": "695013ba7c7c55912d065a6d",
                    "access": {
                        "authentication": "NONE",
                        "complexity": "LOW",
                        "vector": "NETWORK",
                    },
                    "assigner": "cna@vuldb.com",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:o:totolink:t10_firmware:4.1.8cu.5803_b20200521:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "47CB81FA-1CCC-4BE4-A16B-DBAC90971DC1",
                                            "vulnerable": True,
                                        }
                                    ],
                                    "negate": False,
                                    "operator": "OR",
                                },
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:h:totolink:t10:-:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "1C410805-E3D4-4F8C-8DF4-013ACE3937FA",
                                            "vulnerable": False,
                                        }
                                    ],
                                    "negate": False,
                                    "operator": "OR",
                                },
                            ],
                            "operator": "AND",
                        }
                    ],
                    "cvss": 10,
                    "cvss3": 9.8,
                    "cvss3Source": "cna@vuldb.com",
                    "cvss3Time": "2025-12-30T18:16:07.343000",
                    "cvss3Type": "Primary",
                    "cvss3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cvss4": 9.3,
                    "cvss4Source": "cna@vuldb.com",
                    "cvss4Time": "2025-12-30T18:16:07.343000",
                    "cvss4Type": "Secondary",
                    "cvss4Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                    "cvssSource": "cna@vuldb.com",
                    "cvssTime": "2025-12-30T18:16:07.343000",
                    "cvssType": "Secondary",
                    "cvssVector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                    "cvss_data": {
                        "cvss2": {
                            "cna@vuldb.com": [
                                {
                                    "accessComplexity": "LOW",
                                    "accessVector": "NETWORK",
                                    "authentication": "NONE",
                                    "availabilityImpact": "COMPLETE",
                                    "baseScore": 10,
                                    "confidentialityImpact": "COMPLETE",
                                    "integrityImpact": "COMPLETE",
                                    "type": "Secondary",
                                    "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                }
                            ]
                        },
                        "cvss3": {
                            "cna@vuldb.com": [
                                {
                                    "attackComplexity": "LOW",
                                    "attackVector": "NETWORK",
                                    "availabilityImpact": "HIGH",
                                    "baseScore": 9.8,
                                    "confidentialityImpact": "HIGH",
                                    "integrityImpact": "HIGH",
                                    "privilegesRequired": "NONE",
                                    "scope": "UNCHANGED",
                                    "type": "Primary",
                                    "userInteraction": "NONE",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            ]
                        },
                        "cvss4": {
                            "cna@vuldb.com": [
                                {
                                    "attackComplexity": "LOW",
                                    "attackRequirements": "NONE",
                                    "attackVector": "NETWORK",
                                    "baseScore": 9.3,
                                    "exploitMaturity": "NOT_DEFINED",
                                    "privilegesRequired": "NONE",
                                    "subsequent_system_availability": "NONE",
                                    "subsequent_system_confidentiality": "NONE",
                                    "subsequent_system_integrity": "NONE",
                                    "type": "Secondary",
                                    "userInteraction": "NONE",
                                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
                                    "vulnerable_system_availability": "HIGH",
                                    "vulnerable_system_confidentiality": "HIGH",
                                    "vulnerable_system_integrity": "HIGH",
                                }
                            ]
                        },
                    },
                    "cwe": ["CWE-119", "CWE-121"],
                    "epss": "0.00101",
                    "epssMetric": {
                        "lastModified": "2025-12-30T13:31:06",
                        "percentile": "0.28594",
                    },
                    "exploitability3": {
                        "attackcomplexity": "LOW",
                        "attackvector": "NETWORK",
                        "privilegesrequired": "NONE",
                        "scope": "UNCHANGED",
                        "userinteraction": "NONE",
                    },
                    "exploitability4": {
                        "attackcomplexity": "LOW",
                        "attackrequirements": "NONE",
                        "exploitmaturity": "NOT_DEFINED",
                        "privilegesrequired": "NONE",
                        "userinteraction": "NONE",
                    },
                    "exploitabilityScore": 10,
                    "exploitabilityScore3": 3.9,
                    "id": "CVE-2025-14964",
                    "impact": {
                        "availability": "COMPLETE",
                        "confidentiality": "COMPLETE",
                        "integrity": "COMPLETE",
                    },
                    "impact3": {
                        "availability": "HIGH",
                        "confidentiality": "HIGH",
                        "integrity": "HIGH",
                    },
                    "impact4": {
                        "attackvector": "NETWORK",
                        "subsequent_system_availability": "NONE",
                        "subsequent_system_confidentiality": "NONE",
                        "subsequent_system_integrity": "NONE",
                        "vulnerable_system_availability": "HIGH",
                        "vulnerable_system_confidentiality": "HIGH",
                        "vulnerable_system_integrity": "HIGH",
                    },
                    "impactScore": 10,
                    "impactScore3": 5.9,
                    "lastModified": "2025-12-30T18:16:07.343000",
                    "modified": "2025-12-30T18:16:07.343000",
                    "products": ["t10_firmware"],
                    "published": "2025-12-19T19:15:50.213000",
                    "references": [
                        "https://github.com/JackWesleyy/CVE/blob/main/TOTOLINK_T10_BOC.md",
                        "https://vuldb.com/?ctiid.337599",
                        "https://vuldb.com/?id.337599",
                        "https://vuldb.com/?submit.717720",
                        "https://www.totolink.net/",
                    ],
                    "status": "Analyzed",
                    "summary": "A vulnerability has been found in TOTOLINK T10 4.1.8cu.5083_B20200521. This affects the function sprintf of the file /cgi-bin/cstecgi.cgi. Such manipulation of the argument loginAuthUrl leads to stack-based buffer overflow. The attack may be performed from remote.",
                    "vendors": ["totolink"],
                    "vulnerable_configuration": [
                        "cpe:2.3:o:totolink:t10_firmware:4.1.8cu.5803_b20200521:*:*:*:*:*:*:*",
                        "cpe:2.3:h:totolink:t10:-:*:*:*:*:*:*:*",
                    ],
                    "vulnerable_configuration_cpe_2_2": [],
                    "vulnerable_configuration_stems": [
                        "cpe:2.3:o:totolink:t10_firmware",
                        "cpe:2.3:h:totolink:t10",
                    ],
                    "vulnerable_product": [
                        "cpe:2.3:o:totolink:t10_firmware:4.1.8cu.5803_b20200521:*:*:*:*:*:*:*"
                    ],
                    "vulnerable_product_stems": ["cpe:2.3:o:totolink:t10_firmware"],
                }
            ],
        ),
        "total": fields.Integer(
            description="Total amount of returned documents", example=1
        ),
    },
)


@api.route("/query")
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class QueryApi(Resource):
    @api.param(
        "rejected",
        "Hide or show rejected CVEs",
        example="hide/show",
        default="show",
        _in="header",
    )
    @api.param("cvss", "CVSS score", example=6.8, _in="header")
    @api.param(
        "cvssSelect",
        "Select the CVSS score of the CVEs related to cvss_score",
        example="above/equals/below",
        _in="header",
    )
    @api.param(
        "cvssVersion",
        "Select which version of CVSS needs to be queried",
        example="V2/V3",
        default="V3",
        _in="header",
    )
    @api.param(
        "startDate",
        "Earliest time for a CVE",
        example="dd-mm-yyyy or dd-mm-yy format, using - or /",
        _in="header",
    )
    @api.param(
        "endDate",
        "Latest time for a CVE",
        example="dd-mm-yyyy or dd-mm-yy format, using - or /",
        _in="header",
    )
    @api.param(
        "timeSelect",
        "Timeframe for the CVEs, related to the start and end time",
        example="from/until/between/outside",
        _in="header",
    )
    @api.param(
        "timeTypeSelect",
        "Select which time is used for the filter",
        example="modified/published/lastModified",
        _in="header",
    )
    @api.param(
        "skip", "Skip the n latest vulnerabilities", example=50, _in="header", type=int
    )
    @api.param(
        "limit",
        "Limit the amount of vulnerabilities to return",
        example=20,
        _in="header",
        type=int,
    )
    @api.marshal_with(query_entries, skip_none=True)
    def get(self):
        """
        Query for CVE's

        Returns a list of CVEs matching the criteria of the filters specified in the headers.
        """
        f = {
            "rejectedSelect": request.headers.get("rejected"),
            "cvss": request.headers.get("cvss"),
            "cvssSelect": request.headers.get("cvssSelect"),
            "cvssVersion": request.headers.get("cvssVersion"),
            "startDate": request.headers.get("startDate"),
            "endDate": request.headers.get("endDate"),
            "timeSelect": request.headers.get("timeSelect"),
            "timeTypeSelect": request.headers.get("timeTypeSelect"),
            "skip": request.headers.get("skip"),
            "limit": request.headers.get("limit"),
        }

        try:
            skip = int(f["skip"]) if f["skip"] else 0
        except ValueError:
            api.abort(400, "Skip variable should be an integer")

        try:
            limit = int(f["limit"]) if f["limit"] else 0
        except ValueError:
            api.abort(400, "Limit variable should be an integer")

        results = filter_logic(f, skip, limit)

        if len(results) == 0:
            api.abort(404, "")
        else:
            return results

    @api.doc(body=PostBodyRequest)
    @api.response(200, "OK", PostBodyResponse)
    @api.param(
        "format",
        "Specify in which format the results must be returned",
        example="json/xml",
        default="json",
        _in="query",
    )
    def post(self, format_output="json"):
        """
        Free query

        Api endpoint that can be used to freely (within the allowed parameters) query the cve search database.

        The request sample payload displays a request body for a single query; multiple request can be combined within
        a comma separated list and send in a single request. In this case the responses will be send back in a list.
        For each request a separate list entry with the results.
        """
        headers = parse_headers(request.headers)
        database_connection = DatabaseHandler()

        output_format = ["json", "xml"]

        received_format = request.args.get("format", None)

        if received_format is None:
            format_output = format_output
        else:
            format_output = str(received_format)

        if format_output not in output_format:
            api.abort(
                400,
                "Specified output format is not possible; possible options are: {}!".format(
                    output_format
                ),
            )

        try:
            body = request.json
        except Exception:
            return "Could not parse request body", 400

        if isinstance(body, dict):
            result = database_connection.handle_api_json_query(
                JSONApiRequest(headers=headers, body=body)
            )
        elif isinstance(body, list):
            result = []
            for each in body:
                result.append(
                    database_connection.handle_api_json_query(
                        JSONApiRequest(headers=headers, body=each)
                    )
                )

        if isinstance(result, tuple):
            # error response; just return it
            return result
        else:
            if format_output == "json":
                return Response(
                    json.dumps(
                        result, indent=4, sort_keys=True, default=json_util.default
                    ),
                    mimetype="application/json",
                )
            if format_output == "xml":
                return Response(dicttoxml(result), mimetype="text/xml")
