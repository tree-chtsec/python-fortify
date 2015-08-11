from fortify import FPR, Issue, Project, ProjectFactory
import sys

if len(sys.argv) == 1:
	print "Usage:  sys.argv[0] <fpr file>"
	sys.exit(-1)

fpr = sys.argv[1]

fprfile = FPR(fpr)

project = ProjectFactory.create_project(fpr)

project.print_vuln_counts()
# TODO: make this optional
project.print_vulns()