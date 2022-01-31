# (c) Copyright 2022 Aaron Kimball
#
# Run all arduino-dbg unit tests.

import unittest
import sys


def main(argv):
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(unittest.defaultTestLoader.discover(start_dir='.', pattern='test*.py'))

    if result.wasSuccessful():
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
