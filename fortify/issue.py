import os
from decimal import *

# object representing a Fortify issue
class Issue:
    def __init__(self, iid, ruleid, kingdom, type, subtype):
        self.id = iid  # instance ID
        self.ruleid = ruleid
        self.kingdom = kingdom
        self.type = type
        self.subtype = subtype
        self.suppressed = False
        self.hidden = False
        self.metadata = {}

    # Factory method to create an instance from a vulnerability XML object directly
    @classmethod
    def from_vulnerability(cls, vulnerability):
        instance = cls(vulnerability.InstanceID, vulnerability.ClassInfo.ClassID,
                       vulnerability.ClassInfo.Kingdom, vulnerability.ClassInfo.Type,
                       vulnerability.ClassInfo.Subtype if hasattr(vulnerability.ClassInfo, 'Subtype') else None)
        instance._build_metadata(vulnerability)
        return instance

    # augments the metadata dictionary with additional metadata, such as rule metadata
    def add_metadata(self, rulemetadata):
        self.metadata.update(rulemetadata)
        # some of these have different case or strings in the XML so add equivalent versions that
        # Fortify uses for filters
        if 'Accuracy' in self.metadata:
            self.metadata['accuracy'] = Decimal(self.metadata['Accuracy'])
        if 'Impact' in self.metadata:
            self.metadata['impact'] = Decimal(self.metadata['Impact'])
        # Fortify only uses this it seems if the instance probability is not set
        if 'Probability' in self.metadata and 'probability' not in self.metadata:
            self.metadata['probability'] = Decimal(self.metadata['Probability'])
        if 'RemediationEffort' in self.metadata:
            self.metadata['remediation effort'] = Decimal(self.metadata['RemediationEffort'])

    @property
    def analysis(self):
        return self.metadata['analysis'] if 'analysis' in self.metadata else None

    @analysis.setter
    def analysis(self, analysis):
        self.metadata['analysis'] = analysis

    @property
    def suppressed(self):
        return self.metadata['suppressed'] == 'true' if 'suppress' in self.metadata else False

    @suppressed.setter
    def suppressed(self, suppressed):
        self.metadata['suppressed'] = str(suppressed).lower()

    # generate the metadata dictionary for the issue.  Here is an example:
    def _build_metadata(self, vulnerability):
        # add vulnerability metadata
        # TODO: add more
        self.metadata['severity'] = Decimal(vulnerability.InstanceInfo.InstanceSeverity.pyval)
        self.metadata['confidence'] = Decimal(vulnerability.InstanceInfo.Confidence.pyval)
        if hasattr(vulnerability.InstanceInfo, 'MetaInfo'):
            # this probability takes precedence over rule probability
            prob = vulnerability.InstanceInfo.MetaInfo.find("./x:Group[@name='Probability']", namespaces={'x':'xmlns://www.fortifysoftware.com/schema/fvdl'})
            if prob is not None:
                self.metadata['probability'] = Decimal(prob.pyval)
        # /f:FVDL/f:Vulnerabilities/f:Vulnerability[2]/f:AnalysisInfo/f:Unified/f:Context
        if hasattr(vulnerability.AnalysisInfo.Unified.Context, 'ReplacementDefinitions'):
            child = vulnerability.AnalysisInfo.Unified.Context.ReplacementDefinitions
            for thisdef in vulnerability.AnalysisInfo.Unified.Context.ReplacementDefinitions.Def:
                if 'PrimaryLocation.file' in thisdef.attrib:
                    self.metadata['shortfile'] = thisdef.attrib['value']
                elif 'PrimaryLocation.line' in thisdef.attrib:
                    self.metadata['line'] = thisdef.attrib['value']

        if hasattr(vulnerability.AnalysisInfo.Unified.Context, 'FunctionDeclarationSourceLocation'):
            child = vulnerability.AnalysisInfo.Unified.Context.FunctionDeclarationSourceLocation
            self.metadata['file'] = child.attrib['path']
            if 'shortfile' not in self.metadata:
                self.metadata['shortfile'] = os.path.basename(child.attrib['path'])
            if 'line' not in self.metadata:
                self.metadata['line'] = child.attrib['line']
        else:
            # attempt this.  Is this more consistent?
            child = vulnerability.AnalysisInfo.Unified.Trace.Primary.Entry.Node.SourceLocation
            self.metadata['file'] = child.attrib['path']
            if 'shortfile' not in self.metadata:
                self.metadata['shortfile'] = os.path.basename(child.attrib['path'])
            if 'line' not in self.metadata:
                self.metadata['line'] = child.attrib['line']

        if hasattr(vulnerability.AnalysisInfo.Unified.Context, 'Function'):
            child = vulnerability.AnalysisInfo.Unified.Context.Function
            self.metadata['package'] = child.attrib['namespace']
            self.metadata['class'] = child.attrib['enclosingClass']
        elif hasattr(vulnerability.AnalysisInfo.Unified.Context, 'ClassIdent'):
            child = vulnerability.AnalysisInfo.Unified.Context.ClassIdent
            self.metadata['package'] = child.attrib['namespace']
            self.metadata['class'] = None
        else:
            # Fortify builds a package name even in this case. Not sure what data it uses from FVDL.
            self.metadata['package'] = None
            self.metadata['class'] = None

    def _likelihood(self):
        # This comes from Fortify support documentation
        # Likelihood = (Accuracy x Confidence x Probability) / 25
        likelihood = (self.metadata['accuracy'] * self.metadata['confidence'] * self.metadata['probability']) / 25
        return round(likelihood, 1)

    def is_NAI(self):
        return self.analysis == 'Not an Issue'

    @property
    def risk(self):
        # This calculates Fortify Priority Order, which actually uses other metadata to place vulnerabilities
        # into 1 of 4 quadrants of a grid based on thresholds as follows (from Fortify support documentation):
        # - 'Critical' if Impact >=2.5 && Likelihood >= 2.5.
        # - 'High' If Impact >=2.5 && Likelihood < 2.5.
        # - 'Medium' If Impact < 2.5 && Likelihood >= 2.5.
        # - 'Low' if impact < 2.5 && likelihood < 2.5.
        impact = self.metadata['impact']
        likelihood = self._likelihood()

        criticality = None
        if impact >= 2.5 and likelihood >= 2.5:
            #print "Rule ID [%s] Critical:  impact [%d], likelihood [%d], accuracy [%d], confidence [%d], probability[%d]" %
            #    (self.id, impact, self._likelihood(), self.metadata['accuracy'], self.metadata['confidence'], self.metadata['probability'])
            criticality = 'Critical'
        elif impact >= 2.5 > likelihood:
            criticality = 'High'
        elif impact < 2.5 <= likelihood:
            criticality = 'Medium'
        elif impact < 2.5 and likelihood < 2.5:
            criticality = 'Low'

        return criticality
