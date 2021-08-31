from flask_restx import Namespace, Resource, fields

from lib.Query import getBrowseList
from lib.Query import getVersionsOfProduct
from web.restapi.cpe_convert import message

api = Namespace("browse", description="Endpoints for vendor information", path="/")


browseList = api.model(
    "browseList",
    {
        "vendor": fields.List(
            fields.String,
            description="List with vendor names",
            example=[
                ".bbsoftware",
                ".joomclan",
                ".matteoiammarrone",
                "0verkill",
                "1-script",
                "10-4_aps",
                "10-strike",
                "1000guess",
                "1024_cms",
                "1024cms",
                "1024tools",
                "10web",
                "111webcalendar",
                "11in1",
                "11xiaoli_project",
                "1234n",
                "123flashchat",
                "129zou",
                "12net",
                "12planet",
                "133",
                "13enforme",
                "13thmonkey",
                "163",
                "1800contacts",
                "180solutions",
                "1crm",
                "1kxun",
                "1password",
                ".....",
            ],
        )
    },
)

browseListVendor = api.model(
    "browseListVendor",
    {
        "product": fields.List(
            fields.String,
            description="List with producet CPE's",
            example=[
                ".net_core",
                ".net_core_sdk",
                ".net_framework",
                ".net_framework_developer_pack",
                ".net_windows_server",
                "20007_office_system",
                "27mhz_wireless_keyboard",
                "365_apps",
                "access",
                "active_directory",
                "active_directory_application_mode",
                "active_directory_authentication_library",
                "active_directory_federation_services",
                "active_directory_lightweight_directory_service",
                "active_directory_services",
                "activesync",
                "activex",
                "adam",
                "all_windows",
                "....",
            ],
        ),
        "vendor": fields.String(description="Vendor name", example="microsoft"),
    },
)

browseListProduct = api.model(
    "browseVersions",
    {
        "version": fields.List(
            fields.String,
            description="List with product CPEs",
            example=[
                "*:*:*:*:*:*:*:*",
                "1.0:*:*:*:*:*:*:*",
                "1.1:*:*:*:*:*:*:*",
                "2.0:*:*:*:*:*:*:*",
                "....",
            ],
        ),
        "product": fields.String(description="Product name", example=".net_core"),
        "vendor": fields.String(description="Vendor name", example=".microsoft"),
    },
)


@api.route("/browse")
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class BrowseAll(Resource):
    @api.marshal_with(browseList)
    def get(self):
        """
        List vendors

        Returns a list of vendors.
        When the link is called, it will return a list of possible vendors.
        """
        browse_list = getBrowseList(None)

        return browse_list


@api.route("/browse/<vendor>")
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class BrowseAll(Resource):
    @api.marshal_with(browseListVendor)
    def get(self, vendor):
        """
        List products of vendor

        Returns a list of products of a specific vendor.
        When the link is called, it enumerates the products for said vendor.
        """
        browseList = getBrowseList(vendor)

        return browseList


@api.route("/browse/<vendor>/<product>")
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class BrowseProductVersions(Resource):
    @api.marshal_with(browseListProduct)
    def get(self, vendor, product):
        """
        List CPEs of product

        Returns a list of CPEs of a specific product.
        When the link is called, it enumerates the CPEs for said product.
        """
        browse_list = getVersionsOfProduct(product)

        result = {"vendor": vendor, "product": product, "version": browse_list}

        return result
