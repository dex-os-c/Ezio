# sources/data — bundled data sub-package.
#
# This empty package directory exists so that ``importlib.resources``
# can locate ``sources.data.onion_seeds.json`` after ``pip install``.
# The actual JSON file is the only content shipped (see pyproject.toml's
# [tool.setuptools.package-data] entry).
#
# In a local git checkout this directory also lets ``importlib.resources``
# find the file directly without falling back to the parent-walk path
# in sources.seed_manager._resolve_seed_file.