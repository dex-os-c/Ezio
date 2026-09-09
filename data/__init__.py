"""Bundled reference data shipped inside the installed package.

This directory is declared as a package (with this empty ``__init__.py``) so
that setuptools ships its data files inside the wheel at ``<root>/data/`` —
the exact location the runtime resolves via
``os.path.dirname(os.path.dirname(__file__))/data`` from ``extractor/`` and
``monitor/`` (and ``Path(__file__).parent.parent/data`` from ``monitor/``).

Without this, a fresh ``pip install ezio`` produces a package with no
``data/`` directory, and query expansion / shape-checking silently degrade to
structural-signals-only ("Gazetteer snapshot not found",
"Common-word list not found"). See pyproject ``[tool.setuptools.package-data]``.
"""
