
Overview
========

TODO.  Convert this to a markdown README

Installation
============

Install to a user directory on OSX:
```bash
	python setup.py install --user --prefix=
```

Using the command-line utility
================

Usage help
---------

```
usage: Print statistics from a Fortify FPR file [-h] -f FPR [-p] [-c] [-s]
                                                [--high_priority_only]

optional arguments:
  -h, --help            show this help message and exit
  -f FPR, --file FPR    generate stats for FPR
  -p, --project_info    print project and scan info
  -c, --vuln_counts     print vulnerabilities as CSV output
  -s, --vuln_summaries  print vulnerability details as CSV output
  --high_priority_only  For vulnerability summaries: Filters only High
                        Priority relevant issues, which includes Critical/High
                        and excludes anything suppressed, removed, hidden, NAI
```

Print out vulnerability counts for an FPR
------

```bash
$ fprstats.py -f ~/Downloads/MyApp.fpr 
Got [108] issues, [0] hidden, [0] NAI, [0] Suppressed, [0] Removed
```

Print out vulnerability counts as CSV (machine-readable) format
------

```bash
$ fprstats.py -f ~/Downloads/MyApp.fpr -c
Got [108] issues, [0] hidden, [0] NAI, [0] Suppressed, [0] Removed
Critical, High, Medium, Low
0, 15, 0, 93
```

Print a report containing vulnerability summaries as CSV format
-----

```bash
$ fprstats.py -f ~/Downloads/MyApp.fpr -s
Got [108] issues, [0] hidden, [0] NAI, [0] Suppressed, [0] Removed
file_line,path,id,kingdom,type_subtype,severity,nai,filtered,suppressed,removed
MyService.java:100,src/main/java/com/example/www/myapp/services/MyService.java,1BE7DEE63734F7EC117948FACE57A977,Errors,Poor Error Handling: Overly Broad Throws,Low,False,V,False,False
....
```

You can redirect the CSV outputs to a file:

```bash
$ fprstats.py -f ~/Downloads/Flights_gulfstream-discovery-service.fpr -c > /tmp/MyApp.csv
Got [108] issues, [0] hidden, [0] NAI, [0] Suppressed, [0] Removed
```

MyApp.csv contains:

```
$ cat /tmp/MyApp.csv
Critical, High, Medium, Low
0, 15, 0, 93
```

Using the module in another python application
================
```python
	from fortify import ProjectFactory

	project = ProjectFactory.create_project("some/path/to/file.fpr")
    
    # Now, print vulnerability summaries, etc.
    project.print_vuln_counts()
```
