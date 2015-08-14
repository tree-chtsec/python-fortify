#!/usr/bin/python
import argparse

from fortify import ProjectFactory

parser = argparse.ArgumentParser("Print statistics from a Fortify FPR file")
parser.add_argument("-f", "--file", dest="fprfile", required=True,
                  help="generate stats for FPR", metavar="FPR")
parser.add_argument("-p", "--project_info", default=False,
                  action="store_true", dest="print_project_info",
                  help="print project and scan info")
parser.add_argument("-c", "--vuln_counts",
                  action="store_true", dest="print_vuln_counts", default=False,
                  help="print vulnerabilities as CSV output")
parser.add_argument("-s", "--vuln_summaries",
                  action="store_true", dest="print_vuln_summaries", default=False,
                  help="print vulnerability details as CSV output")

args = parser.parse_args()

project = ProjectFactory.create_project(args.fprfile)

if args.print_project_info:
    project.print_project_info()

if args.print_vuln_counts:
    project.print_vuln_counts()

if args.print_vuln_summaries:
    project.print_vuln_summaries()
