'''module to create atom and rss feeds'''
# Feedformatter
# Copyright (c) 2008, Luke Maurits <luke@maurits.id.au>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# * The name of the author may not be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import sys

PY3 = sys.version_info[0] == 3

__version__ = "0.5"
__author__ = "Luke Maurits, Michael Stella, Mariano Guerra"
__copyright__ = "Copyright 2008 Luke Maurits"

if PY3:
    from io import StringIO
    basestring = str
else:

    if sys.version_info[1] < 6:
        bytes = str

    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

# This "staircase" of import attempts is ugly.  If there's a nicer way to do
# this, please let me know!
try:
    import xml.etree.cElementTree as ET
except ImportError:
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        try:
            import cElementTree as ET
        except ImportError:
            try:
                from elementtree import ElementTree as ET
            except ImportError:
                raise ImportError("Could not import any form of element tree!")

try:
    from xml.dom.ext import PrettyPrint
    from xml.dom.ext.reader.Sax import FromXml
    CAN_PRETTY_PRINT = True
except ImportError:
    CAN_PRETTY_PRINT = False

import time
import datetime

def _get_tz_offset():
    """
    Return the current timezone's offset from GMT as a string
    in the format +/-HH:MM, as required by RFC3339.
    """

    seconds = -1 * time.timezone    # Python gets the offset backward! >:(
    minutes = seconds / 60
    hours = minutes / 60
    minutes = minutes - hours * 60
    hours = abs(hours)

    if seconds < 0:
        return "-%02d:%02d" % (hours, minutes)
    else:
        return "+%02d:%02d" % (hours, minutes)

def _convert_datetime(dtime):
    """
    Convert dtime, which may be one of a whole lot of things, into a
    standard 9 part time tuple.
    """

    if type(dtime) is datetime.datetime:
        return dtime.timetuple()
    elif ((type(dtime) is tuple and len(dtime) == 9) or
            type(dtime) is time.struct_time):
        # Already done!
        return dtime
    elif type(dtime) is int or type(dtime) is float:
        # Assume this is a seconds-since-epoch time
        return time.localtime(dtime)
    elif isinstance(dtime, basestring):
        # A time stamp?
        try:
            return time.strptime(dtime, "%a, %d %b %Y %H:%M:%S %Z")
        except ValueError:
            # Maybe this is a string of an epoch time?
            try:
                return time.localtime(float(dtime))
            except ValueError:
                # Guess not.
                raise Exception("Unrecongised time format!")
    else:
        # No idea what this is.  Give up!
        raise Exception("Unrecongised time format!")

def _format_datetime(feed_type, dtime):
    """
    Convert some representation of a date and time into a string which can be
    used in a validly formatted feed of type feed_type.  Raise an
    Exception if this cannot be done.
    """

    # First, convert time into a time structure
    if not type(dtime) is time.struct_time:
        dtime = _convert_datetime(dtime)

    # Then, convert that to the appropriate string
    if feed_type is "rss2":
        return time.strftime("%a, %d %b %Y %H:%M:%S %Z", dtime)
    elif feed_type is "atom":
        return time.strftime("%Y-%m-%dT%H:%M:%S", dtime) + _get_tz_offset()

def _atomise_id(tag):
    """return a tag in a suitable format for atom"""

    if type(tag) is dict:
        return tag['href'].replace('http://', 'tag:')

    return tag.replace('http://', 'tag:')

def _atomise_link(link, rel=None):
    """return a link in a suitable format for atom"""

    if type(link) is dict:
        if 'type' not in link:
            link['type'] = 'text/html'

        if rel and 'rel' not in link:
            link['rel'] = rel

        return link
    else:
        result = {'href' : link, 'type': 'text/html'}

        if rel:
            result['rel'] = rel

        return result

def _atomise_author(author):
    """
    Convert author from whatever it is to a dictionary representing an
    atom:Person construct.
    """

    if type(author) is dict:
        return author
    else:
        if author.startswith("http://") or author.startswith("www"):
            # This is clearly a URI
            return {"uri" : author}
        elif "@" in author and "." in author:
            # This is most probably an email address
            return {"email" : author}
        else:
            # Must be a name
            return {"name" : author}

def _rssify_author(author):
    """
    Convert author from whatever it is to a plain old email string for
    use in an RSS 2.0 feed.
    """

    if type(author) is dict:
        return author.get("email", None)
    else:
        if "@" in author and "." in author:
            # Probably an email address
            return author
        else:
            return None

def _rssify_link(link):
    """return a link in a suitable format"""
    if type(link) is dict:
        return link['href']
    else:
        return link

def _format_content(content):
    """Converts the ATOM 'content' node into a dict,
        which will allow one to pass in a dict which has
        an optionaly 'type' argument
        """

    if type(content) is dict:

        if not 'type' in content:
            content['type'] = 'text'

        return content

    else:
        return {
            'type':     'html',
            'content':  content,
        }

def _add_subelems(root_element, mappings, dictionary):
    """
    Add one subelement to root_element for each key in dictionary
    which is supported by a mapping in mappings
    """

    for mapping in mappings:
        for key in mapping[0]:

            if key in dictionary:

                if len(mapping) == 2:
                    value = dictionary[key]
                elif len(mapping) == 3:
                    value = mapping[2](dictionary[key])

                _add_subelem(root_element, mapping[1], value)

                break

def _add_subelem(root_element, name, value):
    """ad a subelement to *root_element*"""

    if value is None:
        return

    if type(value) is dict:
        ### HORRIBLE HACK!
        if name == "link":
            ET.SubElement(root_element, name, value)

        elif name == 'content':
            # A wee hack too, the content node must be
            # converted to a CDATA block. This is a sort of cheat, see:
            # http://stackoverflow.com
            #   /questions/174890/how-to-output-cdata-using-elementtree
            element = ET.Element(name, type= value['type'])
            element.append(cdata(value['content']))
            root_element.append(element)

        else:
            sub_elem = ET.SubElement(root_element, name)

            for key in value:
                _add_subelem(sub_elem, key, value[key])

    else:
        ET.SubElement(root_element, name).text = value

def _stringify(tree, pretty):
    """
    Turn an ElementTree into a string, optionally with line breaks and indentation.
    """

    if pretty and CAN_PRETTY_PRINT:
        string = StringIO()
        doc = FromXml(_element_to_string(tree))
        PrettyPrint(doc, string, indent="    ")

        return string.getvalue()
    else:
        return _element_to_string(tree)

def _element_to_string(element, encoding=None):
    """
    This replaces ElementTree's tostring() function
    with one that will use our local ElementTreeCDATA
    class instead
    """

    class Dummy(object):
        """a dummy class that has the required fields to be used in
        the write method call below"""

        def __init__(self, write_function):
            self.write = write_function

    data = []

    if encoding is None:
        encoding = 'utf-8'

    file_like = Dummy(data.append)
    ElementTreeCDATA(element).write(file_like, encoding)

    new_data = []

    for item in data:
        if item is None:
            new_item = ""
        elif isinstance(item, bytes):
            new_item = item.decode(encoding)
        else:
            new_item = item

        new_data.append(new_item)

    return ''.join(new_data)

class Feed(object):
    """class that represents a feed object"""

    def __init__(self, feed=None, items=None):

        if feed:
            self.feed = feed
        else:
            self.feed = {}
        if items:
            self.items = items
        else:
            self.items = []
        self.entries = self.items

    ### RSS 1.0 STUFF ------------------------------

    def validate_rss1(self):
        """Raise an InvalidFeedException if the feed cannot be validly
        formatted as RSS 1.0."""

        # <channel> must contain "title"
        if "title" not in self.feed:
            raise InvalidFeedException("The channel element of an "
                "RSS 1.0 feed must contain a title subelement")

        # <channel> must contain "link"
        if "link" not in self.feed:
            raise InvalidFeedException("The channel element of an "
                " RSS 1.0 feeds must contain a link subelement")

        # <channel> must contain "description"
        if "description" not in self.feed:
            raise InvalidFeedException("The channel element of an "
                "RSS 1.0 feeds must contain a description subelement")

        # Each <item> must contain "title" and "link"
        for item in self.items:
            if "title" not in item:
                raise InvalidFeedException("Each item element in an RSS 1.0 "
                    "feed must contain a title subelement")

            if "link" not in item:
                raise InvalidFeedException("Each item element in an RSS 1.0 "
                    "feed must contain a link subelement")

    def format_rss1_string(self, validate=True, pretty=False):
        """Format the feed as RSS 1.0 and return the result as a string."""

        if validate:
            self.validate_rss1()

        rss1_root = ET.Element('rdf:RDF',
            {"xmlns:rdf" : "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
             "xmlns" : "http://purl.org/rss/1.0/"})

        rss1_channel = ET.SubElement(rss1_root, 'channel',
            {"rdf:about" : self.feed["link"]})

        _add_subelems(rss1_channel, _rss1_channel_mappings, self.feed)

        rss1_contents = ET.SubElement(rss1_channel, 'items')
        rss1_contents_seq = ET.SubElement (rss1_contents, 'rdf:Seq')

        for item in self.items:
            ET.SubElement(rss1_contents_seq, 'rdf:li', resource=item["link"])

        for item in self.items:
            rss1_item = ET.SubElement(rss1_root, 'item',
                {"rdf:about" : item["link"]})

            _add_subelems(rss1_item, _rss1_item_mappings, item)

        return _stringify(rss1_root, pretty=pretty)

    def format_rss1_file(self, filename, validate=True, pretty=False):
        """Format the feed as RSS 1.0 and save the result to a file."""

        string = self.format_rss1_string(validate, pretty)
        handle = open(filename, "w")
        handle.write(string)
        handle.close()

    ### RSS 2.0 STUFF ------------------------------

    def validate_rss2(self):
        """Raise an InvalidFeedException if the feed cannot be validly
        formatted as RSS 2.0."""

        # <channel> must contain "title"
        if "title" not in self.feed:
            raise InvalidFeedException("The channel element of an "
                "RSS 2.0 feed must contain a title subelement")

        # <channel> must contain "link"
        if "link" not in self.feed:
            raise InvalidFeedException("The channel element of an "
                " RSS 2.0 feeds must contain a link subelement")

        # <channel> must contain "description"
        if "description" not in self.feed:
            raise InvalidFeedException("The channel element of an "
                "RSS 2.0 feeds must contain a description subelement")

        # Each <item> must contain at least "title" OR "description"
        for item in self.items:
            if not ("title" in item or "description" in item):
                raise InvalidFeedException("Each item element in an RSS 2.0 "
                    "feed must contain at least a title or description"
                    " subelement")

    def format_rss2_string(self, validate=True, pretty=False):
        """Format the feed as RSS 2.0 and return the result as a string."""

        if validate:
            self.validate_rss2()

        rss2_root = ET.Element('rss', {'version':'2.0'})
        rss2_channel = ET.SubElement(rss2_root, 'channel')

        _add_subelems(rss2_channel, _rss2_channel_mappings, self.feed)

        for item in self.items:
            rss2_item = ET.SubElement(rss2_channel, 'item')
            _add_subelems(rss2_item, _rss2_item_mappings, item)

        return ('<?xml version="1.0" encoding="UTF-8" ?>\n' +
            _stringify(rss2_root, pretty=pretty))

    def format_rss2_file(self, filename, validate=True, pretty=False):
        """Format the feed as RSS 2.0 and save the result to a file."""

        string = self.format_rss2_string(validate, pretty)
        handle = open(filename, "w")
        handle.write(string)
        handle.close()

    ### ATOM STUFF ------------------------------

    def validate_atom(self):
        """Raise an InvalidFeedException if the feed cannot be validly
        formatted as Atom 1.0."""

        # Must have at least one "author" element in "feed" OR at least
        # "author" element in each "entry".
        if "author" not in self.feed:
            for entry in self.entries:
                if "author" not in entry:
                    raise InvalidFeedException("Atom feeds must have either at "
                        "least one author element in the feed element or at "
                        " least one author element in each entry element")

    def format_atom_string(self, validate=True, pretty=False):
        """Format the feed as Atom 1.0 and return the result as a string."""

        if validate:
            self.validate_atom()

        atom_root = ET.Element('feed', {"xmlns":"http://www.w3.org/2005/Atom"})
        _add_subelems(atom_root, _atom_feed_mappings, self.feed)

        for entry in self.entries:
            atom_item = ET.SubElement( atom_root, 'entry')
            _add_subelems(atom_item, _atom_item_mappings, entry)

        return ('<?xml version="1.0" encoding="UTF-8" ?>\n' +
                _stringify(atom_root, pretty=pretty))

    def format_atom_file(self, filename, validate=True, pretty=False):
        """Format the feed as Atom 1.0 and save the result to a file."""

        string = self.format_atom_string(validate, pretty)
        handle = open(filename, "w")
        handle.write(string)
        handle.close()

class InvalidFeedException(Exception):
    """Exception thrown when manipulating an invalid feed"""
    pass

def cdata(text=None):
    """create and return a CDATA element"""
    if text is None:
        text = ""

    element = ET.Element("CDATA")
    element.text = text

    return element

class ElementTreeCDATA(ET.ElementTree):
    """
    Subclass of ElementTree which handles CDATA blocks reasonably
    """
    def _write(self, file_like, node, encoding, namespaces):
        """write this element representation to *file_like*"""
        if node.tag == "CDATA":
            text = node.text.encode(encoding)
            file_like.write("\n<![CDATA[%s]]>\n" % text)
        else:
            ET.ElementTree._write(self, file_like, node, encoding, namespaces)

# RSS 1.0 Functions ----------

_rss1_channel_mappings = (
    (("title",), "title"),
    (("link", "url"), "link"),
    (("description", "desc", "summary"), "description")
)

_rss1_item_mappings = (
    (("title",), "title"),
    (("link", "url"), "link"),
    (("description", "desc", "summary"), "description")
)

# RSS 2.0 Functions ----------

_rss2_channel_mappings = (
    (("title",), "title"),
    (("link", "url"), "link", _rssify_link),
    (("description", "desc", "summary"), "description"),
    (("pubDate_parsed", "pubdate_parsed", "date_parsed", "published_parsed", "updated_parsed", "pubDate", "pubdate", "date", "published", "updated"), "pubDate",
        lambda x: _format_datetime("rss2",x)),
    (("category",), "category"),
    (("language",), "language"),
    (("copyright",), "copyright"),
    (("webMaster",), "webmaster"),
    (("image",), "image"),
    (("skipHours",), "skipHours"),
    (("skipDays",), "skipDays")
)

_rss2_item_mappings = (
    (("title",), "title"),
    (("link", "url"), "link", _rssify_link),
    (("description", "desc", "summary"), "description"),
    (("guid", "id"), "guid"),
    (("pubDate_parsed", "pubdate_parsed", "date_parsed", "published_parsed", "updated_parsed", "pubDate", "pubdate", "date", "published", "updated"), "pubDate",
        lambda x: _format_datetime("rss2",x)),
    (("category",), "category"),
    (("author",), "author", _rssify_author)
)

# Atom 1.0 ----------

_atom_feed_mappings = (
    (("title",), "title"),
    (("id", "link", "url"), "id", _atomise_id),
    (("link", "url"), "link", _atomise_link),
    (("description", "desc", "summary"), "subtitle"),
    (("pubDate_parsed", "pubdate_parsed", "date_parsed", "published_parsed", "updated_parsed", "pubDate", "pubdate", "date", "published", "updated"), "updated",
        lambda x: _format_datetime("atom",x)),
    (("category",), "category"),
    (("author",), "author", _atomise_author)
)

_atom_item_mappings = (
    (("title",), "title"),
    (("link", "url"), "link", lambda x: _atomise_link(x, rel='alternate')),
    (("id", "link", "url"), "id", _atomise_id),
    (("description", "desc", "summary"), "summary"),
    (("content",), "content", _format_content),
    (("pubDate_parsed", "pubdate_parsed", "date_parsed", "published_parsed", "updated_parsed", "pubDate", "pubdate", "date", "published", "updated"), "published",
        lambda x: _format_datetime("atom",x)),
    (("updated",), "updated", lambda x: _format_datetime("atom",x)),
    (("category",), "category"),
    (("author",), "author", _atomise_author)
)

### FACTORY FUNCTIONS ------------------------------

def from_ufp(ufp):
    """build a Feed object from an ufp (?)"""
    return Feed(ufp["feed"], ufp["items"])

### MAIN ------------------------------

def main():
    """
    main function called when the module is invoked from the command
    line, display a small demo of the module
    """

    def show(*args):
        """a cross version replacement for print that is useful for the demo
        here"""
        sys.stdout.write(" ".join([str(arg) for arg in args]))
        sys.stdout.write("\n")

    feed = Feed()
    feed.feed["title"] = "Test Feed"
    feed.feed["link"] = "http://code.google.com/p/feedformatter/"
    feed.feed["author"] = "Luke Maurits"
    feed.feed["description"] = "A simple test feed for feedformatter"

    item = {}
    item["title"] = "Test item"
    item["link"] = "http://www.python.org"
    item["description"] = "Python programming language"
    item["guid"] = "1234567890"

    feed.items.append(item)

    show("---- RSS 1.0 ----")
    show(feed.format_rss1_string(pretty=True))
    show("---- RSS 2.0 ----")
    show(feed.format_rss2_string(pretty=True))
    show("---- Atom 1.0 ----")
    show(feed.format_atom_string(pretty=True))

if __name__ == "__main__":
    main()
