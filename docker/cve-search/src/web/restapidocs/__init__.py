from flask import Blueprint

docs = Blueprint("docs", __name__, static_folder="docs")


@docs.route("/api_docs")
def doc_root():
    return docs.send_static_file("index.html")
