#!/usr/local/bin/python3.10
# -*- coding: utf-8 -*-
import re
import sys
<<<<<<< HEAD
from aixblock_core.server import main
=======

# Initialize security components before starting the server
try:
    from security import initialize_security
    initialize_security()
except Exception as e:
    print(f"Warning: Security initialization failed: {e}")

from aixblock_core.server import main

>>>>>>> 01282aa (Initial commit for bugreport/issue-101)
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    main()