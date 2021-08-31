from flask_restx import Resource, Namespace, fields

from lib.Query import searchVendors, searchProductsByVendor, searchVersionsByProduct
from web.restapi.cpe_convert import message

api = Namespace(
    "search-vendor",
    description="Endpoints to search vendor information by providing part strings.",
    path="/",
)

search_vendor_model = api.model(
    "browseList",
    {
        "vendor": fields.List(
            fields.String,
            description="List with vendor names matching the given part",
            example=[".bbsoftware", ".joomclan", ".matteoiammarrone", "....."],
        )
    },
)


@api.route("/search-vendor/<vendor_part>")
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class SearchVendors(Resource):
    @api.marshal_with(search_vendor_model)
    def get(self, vendor_part):
        """
        Search vendors

        Returns a list of vendors that match the given part-string.
        """
        return searchVendors(vendor_part)


search_product_by_vendor_model = api.model(
    "browseListVendor",
    {
        "product": fields.List(
            fields.String,
            description="List with product names belonging to the given vendor that match the given part string",
            example=[".net_core", ".net_core_sdk", ".net_framework", "...."],
        ),
        "vendor": fields.String(description="Vendor name", example="microsoft"),
    },
)


@api.route("/search-vendor/<vendor>/<product_part>")
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class SearchProductsByVendor(Resource):
    @api.marshal_with(search_product_by_vendor_model)
    def get(self, vendor, product_part):
        """
        Search products by vendor

        Returns a list of products that match the given vendor and part-string.
        """
        return searchProductsByVendor(vendor, product_part)


search_version_by_product_model = api.model(
    "browseVersions",
    {
        "version": fields.List(
            fields.String,
            description="List with versions belonging to the given product that match the given part string",
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


@api.route("/search-vendor/<vendor>/<product>/<version_part>")
@api.response(400, "Error processing request", model=message)
@api.response(500, "Server error", model=message)
class SearchVersionsByProduct(Resource):
    @api.marshal_with(search_version_by_product_model)
    def get(self, vendor, product, version_part):
        """
        Search CPEs by vendor and product.

        Returns a list of CPEs that match the given vendor, product and version part-string.
        """
        return searchVersionsByProduct(vendor, product, version_part)
