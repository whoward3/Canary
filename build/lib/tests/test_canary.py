"""
test_canary
Description: Unit tests for canary scripts using unittests
Author: Winston Howard
Created Date: 04/28/20
 
 
Canary
Copyright (C) 2020  Winston Howard

See the LICENSE file included in this distribution.
"""

import unittest
import queue
from .. import canaryScripts as s

class SimpleSharkTestCase(unittest.TestCase):
    """
    A simple test case for the canary_shark python script
    """

    # testing canary shark evaluation function, on entropy list < threshold
    def evaluator_test(self):
        ip_dict = {
                    "10.42.0.1": 1,
                    "10.42.0.2": 1,
                    "10.42.0.3": 48,                    
                  }
        _log = queue.Queue()

        res = s.canary_shark.CanaryShark.evalutator(ip_dict,_log,0,1)
        self.assertEqual(res,0)

if __name__ == '__main__':
    unittest.main()