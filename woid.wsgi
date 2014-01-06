#!/usr/bin/env python

import os, site, sys

thisdir = os.path.dirname(__file__)

venvs = [thisdir]
venv_paths = []

for venv in venvs:
    venv_paths.append(os.path.join(venv, 'lib','python2.7','site-packages')) # This sucks...
    # If you installed via pip -e, then you we are placed in venvdir/src/package/
    # so we go two levels up. Yes. That is annoying.
    venv_paths.append(os.path.join(venv, '..', '..', 'lib','python2.7','site-packages'))


# Copied from http://code.google.com/p/modwsgi/wiki/VirtualEnvironments
# Remember original sys.path.
prev_sys_path = list(sys.path)


for venv_path in venv_paths:
    site.addsitedir(venv_path)
    #sys.path.insert(0, venv_path)

# Reorder sys.path so new directories at the front.
new_sys_path = [] 
for item in list(sys.path): 
    if item not in prev_sys_path: 
        new_sys_path.append(item) 
        sys.path.remove(item) 
sys.path[:0] = new_sys_path

import ownopenidserver
from ownopenidserver.wideopenidserver import init

application = init(os.path.join(os.path.sep, 'tmp', 'wideopenid', 'store')).wsgifunc()
