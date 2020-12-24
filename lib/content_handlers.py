from collections import defaultdict
from xml.sax.handler import ContentHandler


class CapecHandler(ContentHandler):
    def __init__(self):
        self.capec = []
        self.Attack_Pattern_Catalog_tag = False
        self.Attack_Patterns_tag = False
        self.Attack_Pattern_tag = False
        self.Attack_step_tag = False
        self.Description_tag = False
        self.Text_tag = False
        self.Prerequisites_tag = False
        self.Prerequisite_tag = False
        self.Mitigations_tag = False
        self.Mitigation_tag = False
        self.Related_Weaknesses_tag = False
        self.Related_Weakness_tag = False
        self.CWE_ID_tag = False
        self.Related_Attack_Patterns = False
        self.Taxonomy_Mappings = False
        self.Taxonomy_Mapping = False
        self.Likelihood_Of_Attack = False
        self.Typical_Severity = False

        self.Execution_Flow = False
        self.Step = True
        self.Phase = True
        self.Attack_Description = True
        self.Technique = True

        self.entry_id = False
        self.entry_name = False

        self.tag = False

        self.id = ""
        self.name = ""

        self.Summary_ch = ""
        self.Prerequisite_ch = ""
        self.Mitigation_ch = ""
        self.CWE_ID_ch = ""
        self.entry_id_ch = ""
        self.entry_name_ch = ""

        self.taxonomy_name = ""
        self.step_name = ""

        self.Step_ch = ""
        self.Phase_ch = ""
        self.Attack_Description_ch = ""
        self.Technique_ch = ""
        self.Likelihood_Of_Attack_ch = ""
        self.Typical_Severity_ch = ""
        self.loa = ""
        self.ts = ""

        self.Summary = []
        self.Prerequisite = []
        self.Solution_or_Mitigation = []
        self.Related_Weakness = []
        self.Related_AttackPatterns = []
        self.techniques = []

        self.taxonomy_mapping = defaultdict(dict)

        self.execution_flow = defaultdict(dict)

    def startElement(self, name, attrs):

        if name == "Attack_Pattern_Catalog":
            self.Attack_Pattern_Catalog_tag = True
        if name == "Attack_Patterns" and self.Attack_Pattern_Catalog_tag:
            self.Attack_Patterns_tag = True
        if name == "Attack_Pattern" and self.Attack_Patterns_tag:
            self.Attack_Pattern_tag = True

        if self.Attack_Pattern_tag:
            self.tag = name
            if self.tag == "Attack_Pattern":
                self.id = attrs.getValue("ID")
                self.name = attrs.getValue("Name")

            if self.tag == "Related_Attack_Patterns":
                self.Related_Attack_Patterns = True

            if self.tag == "Related_Attack_Pattern" and self.Related_Attack_Patterns:
                self.Related_AttackPatterns.append(attrs.get("CAPEC_ID"))

            if self.tag == "Taxonomy_Mappings":
                self.Taxonomy_Mappings = True

            if self.tag == "Taxonomy_Mapping" and self.Taxonomy_Mappings:
                self.Taxonomy_Mapping = True
                self.taxonomy_name = attrs.get("Taxonomy_Name")

            if self.tag == "Entry_ID" and self.Taxonomy_Mappings:
                self.entry_id = True
                self.entry_id_ch = ""

            if self.tag == "Entry_Name" and self.Taxonomy_Mappings:
                self.entry_name = True
                self.entry_name_ch = ""

            if self.tag == "Execution_Flow":
                self.Execution_Flow = True

            if self.tag == "Attack_Step" and self.Execution_Flow:
                self.Attack_step_tag = True

            if self.tag == "Step" and self.Attack_step_tag:
                self.Step = True
                self.Step_ch = ""

            if self.tag == "Phase" and self.Attack_step_tag:
                self.Phase = True
                self.Phase_ch = ""

            if self.tag == "Description" and self.Attack_step_tag:
                self.Attack_Description = True
                self.Attack_Description_ch = ""

            if self.tag == "Technique" and self.Attack_step_tag:
                self.Technique = True
                self.Technique_ch = ""

            if self.tag == "Description" and not self.Attack_step_tag:
                self.Description_tag = True
                self.Summary_ch = ""

            if self.tag == "Prerequisites":
                self.Prerequisites_tag = True
            if name == "Prerequisite" and self.Prerequisites_tag:
                self.Prerequisite_tag = True
                self.Prerequisite_ch = ""

            if self.tag == "Mitigations":
                self.Mitigations_tag = True
            if name == "Mitigation" and self.Mitigations_tag:
                self.Mitigation_tag = True
            if name == "xhtml:p" and self.Mitigation_tag:
                self.Text_tag = True
                self.Mitigation_ch = ""

            if self.tag == "Related_Weaknesses":
                self.Related_Weaknesses_tag = True
            if name == "Related_Weakness" and self.Related_Weaknesses_tag:
                self.Related_Weakness.append(attrs.getValue("CWE_ID"))

            if self.tag == "Likelihood_Of_Attack":
                self.Likelihood_Of_Attack = True
                self.Likelihood_Of_Attack_ch = ""

            if self.tag == "Typical_Severity":
                self.Typical_Severity = True
                self.Typical_Severity_ch = ""

    def characters(self, ch):
        if self.Description_tag:
            self.Summary_ch += ch

        if self.Prerequisite_tag:
            self.Prerequisite_ch += ch

        if self.Text_tag:
            if self.Mitigation_tag:
                self.Mitigation_ch += ch

        if self.entry_id:
            self.entry_id_ch += ch

        if self.entry_name:
            self.entry_name_ch += ch

        if self.Step:
            self.Step_ch += ch

        if self.Phase:
            self.Phase_ch += ch

        if self.Attack_Description:
            self.Attack_Description_ch += ch

        if self.Technique:
            self.Technique_ch += ch

        if self.Likelihood_Of_Attack:
            self.Likelihood_Of_Attack_ch += ch

        if self.Typical_Severity:
            self.Typical_Severity_ch += ch

    def endElement(self, name):
        if name == "Description" and not self.Attack_step_tag:
            self.Summary.append(self.Summary_ch.rstrip())
            if self.Summary_ch != "":
                self.Summary_ch = ""
            self.Description_tag = False

        if name == "Entry_ID":
            self.entry_id = False

        if name == "Entry_Name":
            self.entry_name = False

            entry_id = self.entry_id_ch.rstrip()

            cut_entry = entry_id.split(".")

            url = ""

            if self.taxonomy_name == "ATTACK":
                if len(cut_entry) == 1:
                    # no subtechnique use plain entry_id
                    url = "https://attack.mitre.org/techniques/T{}".format(entry_id)
                else:
                    # attack with subtechniques use cut_entry
                    url = "https://attack.mitre.org/techniques/T{}/{}".format(cut_entry[0], cut_entry[1])

            elif self.taxonomy_name == "WASC":

                if "/" in self.entry_name_ch:
                    url = "http://projects.webappsec.org/{}".format(self.entry_name_ch.replace("/", " and ").replace(" ",  "-"))
                else:
                    url = "http://projects.webappsec.org/{}".format(self.entry_name_ch.replace(" ", "-"))

            elif self.taxonomy_name == "OWASP Attacks":
                entry_id = "Link"

                url = "https://owasp.org/www-community/attacks/{}".format(self.entry_name_ch.replace(" ", "_"))

            self.taxonomy_mapping[self.taxonomy_name][self.entry_id_ch.rstrip().replace(".", "_")] = {
                "Entry_ID": entry_id,
                "Entry_Name": self.entry_name_ch.rstrip(),
                "URL": url,
            }

            if self.entry_id_ch != "":
                self.entry_id_ch = ""

            if self.entry_name_ch != "":
                self.entry_name_ch = ""

        if name == "Taxonomy_Mappings":
            self.Taxonomy_Mappings = False

        if name == "Taxonomy_Mapping":
            self.Taxonomy_Mapping = False

        if name == "Step":
            self.step_name = self.Step_ch.rstrip()
            self.Step = False

        if name == "Phase":
            self.Phase = False

        if name == "Description" and self.Attack_step_tag:
            self.Attack_Description = False

            self.execution_flow[self.step_name] = {
                "Phase": self.Phase_ch.rstrip(),
                "Description": self.Attack_Description_ch.rstrip(),
                "Techniques": []
            }

            if self.Step_ch != "":
                self.Step_ch = ""

            if self.Phase_ch != "":
                self.Phase_ch = ""

            if self.Attack_Description_ch != "":
                self.Attack_Description_ch = ""

        if name == "Technique" and self.Attack_step_tag:
            if self.Technique_ch != "":
                self.execution_flow[self.step_name]["Techniques"].append(self.Technique_ch.rstrip())
                self.Technique_ch = ""
            self.Technique = False

        if name == "Attack_Step":
            self.Attack_step_tag = False

        if name == "Execution_Flow":
            self.Execution_Flow = False

        if name == "Prerequisite":
            if self.Prerequisite_ch != "":
                self.Prerequisite.append(self.Prerequisite_ch.rstrip())
            self.Prerequisite_tag = False
        if name == "Mitigation":
            if self.Mitigation_ch != "":
                self.Solution_or_Mitigation.append(self.Mitigation_ch.rstrip())
                self.Mitigation_ch = ""
            self.Mitigation_tag = False

        if name == "Prerequisites":
            self.Prerequisites_tag = False
        if name == "Mitigations":
            self.Mitigations_tag = False
        if name == "Related_Weaknesses":
            self.Related_Weaknesses_tag = False

        if name == "Related_Attack_Patterns":
            self.Related_Attack_Patterns = False

        if name == "Likelihood_Of_Attack":
            self.Likelihood_Of_Attack = False
            self.loa = self.Likelihood_Of_Attack_ch.rstrip()
            self.Likelihood_Of_Attack_ch = ""

        if name == "Typical_Severity":
            self.Typical_Severity = False
            self.ts = self.Typical_Severity_ch.rstrip()
            self.Typical_Severity_ch = ""

        if name == "Attack_Pattern":
            if not self.name.startswith("DEPRECATED"):
                self.capec.append(
                    {
                        "name": self.name,
                        "id": self.id,
                        "summary": "\n".join(self.Summary),
                        "prerequisites": " ".join(self.Prerequisite),
                        "solutions": " ".join(self.Solution_or_Mitigation),
                        "related_capecs": sorted(self.Related_AttackPatterns),
                        "related_weakness": sorted(self.Related_Weakness),
                        "taxonomy": dict(self.taxonomy_mapping),
                        "execution_flow": dict(self.execution_flow),
                        "loa": self.loa,
                        "typical_severity": self.ts,
                    }
                )
            self.Summary = []
            self.Prerequisite = []
            self.Solution_or_Mitigation = []
            self.Related_Weakness = []
            self.Related_AttackPatterns = []
            self.techniques = []

            self.taxonomy_mapping = defaultdict(dict)

            self.execution_flow = defaultdict(dict)

            self.Attack_Pattern_tag = False
        if name == "Attack_Patterns":
            self.Attack_Patterns_tag = False
        if name == "Attack_Pattern_Catalog":
            self.Attack_Pattern_Catalog_tag = False


class CWEHandler(ContentHandler):
    def __init__(self):
        self.cwe = []
        self.description_tag = False
        self.category_tag = False
        self.weakness_tag = False
        self.weakness_relationships_tag = False
        self.category_relationships_tag = False

    def startElement(self, name, attrs):

        if name == "Weakness":
            self.weakness_tag = True
            self.statement = ""
            self.weaknessabs = attrs.get("Abstraction")
            self.name = attrs.get("Name")
            self.idname = attrs.get("ID")
            self.status = attrs.get("Status")
            if not self.name.startswith("DEPRECATED"):
                self.cwe.append(
                    {
                        "name": self.name,
                        "id": self.idname,
                        "status": self.status,
                        "weaknessabs": self.weaknessabs,
                    }
                )

        elif name == "Category":
            self.category_tag = True
            self.category_name = attrs.get("Name")
            self.category_id = attrs.get("ID")
            self.category_status = attrs.get("Status")
            if not self.category_name.startswith("DEPRECATED"):
                self.cwe.append(
                    {
                        "name": self.category_name,
                        "id": self.category_id,
                        "status": self.category_status,
                        "weaknessabs": "Category",
                    }
                )

        elif name == "Description" and self.weakness_tag:
            self.description_tag = True
            self.description = ""

        elif name == "Summary" and self.category_tag:
            self.description_tag = True
            self.description = ""

        elif name == "Relationships" and self.category_tag:
            self.category_relationships_tag = True
            self.relationships = []

        elif name == "Related_Weaknesses" and self.weakness_tag:
            self.weakness_relationships_tag = True
            self.relationships = []

        elif name == "Related_Weakness" and self.weakness_relationships_tag:
            self.relationships.append(attrs.get("CWE_ID"))

        elif name == "Has_Member" and self.category_relationships_tag:
            self.relationships.append(attrs.get("CWE_ID"))

    def characters(self, ch):
        if self.description_tag:
            self.description += ch.replace("       ", "")

    def endElement(self, name):
        if name == "Description" and self.weakness_tag:
            self.description_tag = False
            self.description = self.description + self.description
            self.cwe[-1]["Description"] = self.description.replace("\n", "")
        if name == "Summary" and self.category_tag:
            self.description_tag = False
            self.description = self.description + self.description
            self.cwe[-1]["Description"] = self.description.replace("\n", "")
        elif name == "Weakness" and self.weakness_tag:
            self.weakness_tag = False
        elif name == "Category" and self.category_tag:
            self.category_tag = False

        elif name == "Related_Weaknesses" and self.weakness_tag:
            self.weakness_relationships_tag = False
            self.cwe[-1]["related_weaknesses"] = self.relationships

        elif name == "Relationships" and self.category_tag:
            self.category_relationships_tag = False
            self.cwe[-1]["relationships"] = self.relationships
