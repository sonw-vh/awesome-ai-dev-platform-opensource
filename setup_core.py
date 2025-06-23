#!/usr/local/bin/python3.10
# -*- coding: utf-8 -*-
import re
import shutil
import sys
from os import makedirs
<<<<<<< HEAD
=======

# Initialize security components during setup
try:
    from security import initialize_security
    initialize_security()
except Exception as e:
    print(f"Warning: Security initialization during setup failed: {e}")

>>>>>>> 01282aa (Initial commit for bugreport/issue-101)
from aixblock_core.server import initialize_database, _setup_env
from django.core.management import call_command

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    _setup_env()
    call_command('migrate')
    makedirs("static", 0o775, True)
    initialize_database()
    shutil.rmtree("static")
