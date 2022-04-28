#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------
# CPE format conversions using a WFN object
# Usage example:
# cpe_uri_to_fs("cpe:/a:fmt:fmt:5.2.0") -> "cpe:2.3:a:fmt:fmt:5.2.0:*:*:*:*:*:*:*"
# cpe_fs_to_uri(""cpe:2.3:a:fmt:fmt:5.2.0:*:*:*:*:*:*:*"") -> "cpe:/a:fmt:fmt:5.2.0"
# Reference specification sheet: https://www.govinfo.gov/content/pkg/GOVPUB-C13-c213837a04c3bcc778ebfd420c6a3f2a/pdf/GOVPUB-C13-c213837a04c3bcc778ebfd420c6a3f2a.pdf
# -----------------------------------------------------------

import re

# Convert cpe2.2 url encoded to cpe2.3 char escaped
# cpe:2.3:o:cisco:ios:12.2%281%29 to cpe:2.3:o:cisco:ios:12.2\(1\)
def unquote(cpe):
    return re.compile("%([0-9a-fA-F]{2})", re.M).sub(
        lambda m: "\\" + chr(int(m.group(1), 16)), cpe
    )


# Convert cpe2.3 char escaped to cpe2.2 url encoded
# cpe:2.3:o:cisco:ios:12.2\(1\) to cpe:2.3:o:cisco:ios:12.2%281%29
def quote(cpe):
    cpe = cpe.replace("\\-", "-")
    cpe = cpe.replace("\\.", ".")
    return re.compile("\\\\(.)", re.M).sub(
        lambda m: "%" + hex(ord(m.group(1)))[2:], cpe
    )


class WFN:
    # Default every value to * which is ANY
    part = "*"
    vendor = "*"
    product = "*"
    version = "*"
    update = "*"
    edition = "*"
    language = "*"
    sw_edition = "*"
    target_sw = "*"
    target_hw = "*"
    other = "*"

    # Pack entries unsupported by URI (CPE2.2) representation in to an extended edition string
    # As described in part 6.1.2.1.3 of the specification
    def pack_edition(self) -> str:
        packed_edition = self.edition
        if (
            self.sw_edition != "*"
            or self.target_hw != "*"
            or self.target_sw != "*"
            or self.other != "*"
        ):
            packed_edition = "~{}~{}~{}~{}~{}".format(
                self.edition,
                self.sw_edition,
                self.target_sw,
                self.target_hw,
                self.other,
            ).replace(
                "*", ""
            )  # ANY values in packed edition are empty
        return packed_edition

    # Unpack entries from extended edition string
    def unpack_edition(self, edition_string: str):
        # The packed edition string should always have the same amount of columns if present
        # If there is less its malformed or not a packed edition
        if edition_string.count("~") == 5:
            edition_components = edition_string.split("~")

            if edition_components[1]:
                self.edition = edition_components[1]

            if edition_components[2]:
                self.sw_edition = edition_components[2]

            if edition_components[3]:
                self.target_sw = edition_components[3]

            if edition_components[4]:
                self.target_hw = edition_components[4]

            if edition_components[5]:
                self.other = edition_components[5]
        else:
            self.edition = edition_string

    # Bind values from WFN object to a CPE URI (2.2)
    def bind_to_uri(self) -> str:
        cpe_uri = "cpe:/{}:{}:{}:{}:{}:{}:{}".format(
            self.part,
            self.vendor,
            self.product,
            self.version,
            self.update,
            self.pack_edition(),
            self.language,
        )
        # Any values are * in the object but CPE URIs use empty columns as any
        cpe_uri = cpe_uri.replace(":*", ":").strip(":")
        return cpe_uri

    # Bind values from WFN to a CPE formatted string (2.3)
    def bind_to_fs(self) -> str:
        cpe_fs = "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}".format(
            self.part,
            self.vendor,
            self.product,
            self.version,
            self.update,
            self.edition,
            self.language,
            self.sw_edition,
            self.target_sw,
            self.target_hw,
            self.other,
        )
        # Convert sequences like for example "%28" (URI format) to "\(" (FS format)
        cpe_fs = unquote(cpe_fs).strip(":")

        return cpe_fs

    # Unbinds WFN values from a CPE URI (2.2 format)
    def unbind_from_uri(self, cpe_uri: str):
        cpe_components = cpe_uri.split(":")
        # Using a loop to easily deal with variable length CPE uris
        for i, comp in enumerate(cpe_components):
            # URI any values are empty while this object uses * for any
            if comp == "":
                comp = "*"
            if i == 1:
                # Simply splitting by : leaves a stray / in the first column so lets remove it
                self.part = comp.replace("/", "")
            elif i == 2:
                self.vendor = comp
            elif i == 3:
                self.product = comp
            elif i == 4:
                self.version = comp
            elif i == 5:
                self.update = comp
            elif i == 6:
                self.unpack_edition(comp)
            elif i == 7:
                self.language = comp

    # Unbinds WFN values from a CPE FS (2.3 format)
    def unbind_from_fs(self, cpe_fs: str):
        # Convert special character sequences such as "\:" to URI format e.g. "%3a" before splitting
        cpe_fs = quote(cpe_fs)
        cpe_components = cpe_fs.split(":")
        # Using a loop to easily deal with variable length CPE format strings
        for i, comp in enumerate(cpe_components):
            if i == 2:
                self.part = comp
            elif i == 3:
                self.vendor = comp
            elif i == 4:
                self.product = comp
            elif i == 5:
                self.version = comp
            elif i == 6:
                self.update = comp
            elif i == 7:
                self.edition = comp
            elif i == 8:
                self.language = comp
            elif i == 9:
                self.sw_edition = comp
            elif i == 10:
                self.target_sw = comp
            elif i == 11:
                self.target_hw = comp
            elif i == 12:
                self.other = comp


# Convert CPE 2.2 format (URI) to CPE 2.3 format (FS)
def cpe_uri_to_fs(uri: str) -> str:
    wfn = WFN()
    wfn.unbind_from_uri(uri)
    return wfn.bind_to_fs()


# Convert CPE 2.3 format (FS) to CPE 2.2 format (URI)
def cpe_fs_to_uri(fs: str) -> str:
    wfn = WFN()
    wfn.unbind_from_fs(fs)
    return wfn.bind_to_uri()
