========
Overview
========

TODO.  Convert this to a markdown README

============
Installation
============

Install to a user directory on OSX:
.. code-block:: bash
	python setup.py install --user --prefix=

================
Using the module
================
.. code-block:: python
	from fortify import ProjectFactory

	project = ProjectFactory.create_project("some/path/to/file.fpr")
