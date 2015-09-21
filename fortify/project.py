from . import FPR, Issue, RemovedIssue

# configures fortify project objects
class ProjectFactory:
    # creates a new project object by loading the FPR from fprpath and building necessary data structures
    def __init__(self):
        pass

    @staticmethod
    def create_project(fprpath):
        fpr = FPR(fprpath)

        project = Project(fpr)

        # find every vulnerability and model as an Issue object attached to the project
        for vuln in fpr.FVDL.get_vulnerabilities():
            issue = Issue.from_vulnerability(vuln)

            ruleinfo = fpr.FVDL.EngineData.RuleInfo.xpath("./x:Rule[@id='%s']" % vuln.ClassInfo.ClassID,
                                                              namespaces={'x':'xmlns://www.fortifysoftware.com/schema/fvdl'})
            if len(ruleinfo) > 0:
                issue.add_metadata(ruleinfo[0].metadata)

            # now, we need to apply visibility rules from the filtertemplate, if one exists, for the
            if fpr.FilterTemplate is not None:
                issue.hidden = fpr.FilterTemplate.is_hidden(fpr, issue)

            project.add_or_update_issue(issue)

        # now, associate the analysis info with the issues we know about.
        # Only FPRs with audit information will have this to associate.
        issues = project.get_issues()
        for issueid in issues:

            i = project.get_issue(issueid)
            ai = fpr.Audit.find("./ns2:IssueList/ns2:Issue[@instanceId='%s']" % i.id, namespaces={'ns2':'xmlns://www.fortify.com/schema/audit'})
            if ai is not None:
                # set suppressed status
                i.suppressed = True if 'suppressed' in ai.attrib and ai.attrib['suppressed'] == 'true' else False
                # This ideally depends on the project template I believe for what Tag values should be but hard-coding
                # for now should be reasonably safe.
                analysis = ai.find("./ns2:Tag[@id='87f2364f-dcd4-49e6-861d-f8d3f351686b']/ns2:Value", namespaces={'ns2':'xmlns://www.fortify.com/schema/audit'})
                if analysis is not None:
                    i.analysis = analysis.text

            project.add_or_update_issue(i)  # add it back in to replace the previous one

        # now, add information about removed issues
        if hasattr(fpr.Audit, 'IssueList') and hasattr(fpr.Audit.IssueList, 'RemovedIssue'):
            for removed in fpr.Audit.IssueList.RemovedIssue:
                ri = RemovedIssue.from_auditxml(removed)
                project.add_or_update_issue(ri)

        removedissues = [i for i in issues.values() if i.removed]
        suppressedissues = [i for i in issues.values() if i.suppressed]
        hiddenissues = [i for i in issues.values() if i.hidden]
        naiissues = [i for i in issues.values() if i.is_NAI()]
        print "Got [%d] issues, [%d] hidden, [%d] NAI, [%d] Suppressed, [%d] Removed" % (len(issues), len(hiddenissues), len(naiissues), len(suppressedissues), len(removedissues))

        return project  # A fortify project, containing one or more issues, with metadata


class Project:
    def __init__(self, fpr):
        self._fpr = fpr
        self._issues = {}

        # set project properties
        if hasattr(fpr.Audit.ProjectInfo, 'Name'):
            self.ProjectName=fpr.Audit.ProjectInfo.Name
        else:
            self.ProjectName=None

        if hasattr(fpr.Audit.ProjectInfo, 'ProjectVersionId'):
            self.ProjectVersionId=fpr.Audit.ProjectInfo.ProjectVersionId
        else:
            self.ProjectVersionId=None

        for loc in fpr.FVDL.Build.LOC:
            if loc.attrib['type'] == 'Fortify':
                self.ScannedELOC=loc.text
            elif loc.attrib['type'] == 'Line Count':
                self.ScannedLOC=loc.text

    def add_or_update_issue(self, issue):
        if issue.id in self._issues:
            # remove first and decrement counts, if change in severity
            current = self._issues[issue.id]
            if issue != current:
                # unless this is a new object, nothing to do
                del self._issues[issue.id]

        # add the issue to the list, if necessary
        self._issues[issue.id] = issue

    def get_issues(self):
        return self._issues

    def get_issue(self, id):
        return self._issues[id]

    def print_project_info(self):
        # TODO: print an overview of the project information (name, etc.) and scan information
        return

    def print_vuln_counts(self):
        vuln_counts = {'Critical': 0,
                        'High': 0,
                        'Medium': 0,
                        'Low': 0,
                        }
        for i in self._issues.values():
            # exclude hidden, NAI and suppressed (TODO: could be configurable)
            if not (i.hidden or i.is_NAI() or i.suppressed):
                if i.risk is None:
                    print "Risk calculation error for issue [%s]" % i.id
                else:
                    vuln_counts[i.risk] += 1

        print "Critical, High, Medium, Low"
        print "%d, %d, %d, %d" % (vuln_counts['Critical'], vuln_counts['High'], vuln_counts['Medium'], vuln_counts['Low'])

    def print_vuln_summaries(self, open_high_priority):
        # TODO: enable sorting by severity and file_line by default.
        print "file_line,path,id,kingdom,type_subtype,severity,nai,filtered,suppressed,removed"
        for i in self._issues.itervalues():
            if not open_high_priority or i.is_open_high_priority:
                print "%s:%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % \
                      (i.metadata['shortfile'], i.metadata['line'], i.metadata['file'], i.id, i.kingdom, i.category, i.risk, i.is_NAI(), "H" if i.hidden else "V", i.suppressed, i.removed)

    def get_fpr(self):
        return self._fpr
