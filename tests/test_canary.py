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
from canaryScripts.canary_shark import CanaryShark

class SimpleSharkTestCase(unittest.TestCase):
    """
    A simple test case for the canary_shark python script
    """

    # testing canary shark evaluation function, on entropy list < threshold
    def test_evaluator(self):
        i_dict = {
                    "10.42.0.1": 1,
                    "10.42.0.2": 2,
                    "10.42.0.3": 47,                    
                  }
        log = queue.Queue()
        res = CanaryShark.evalutator(ip_dict = i_dict,_log = log,bridge_id=0,thresh=0.3826)
        self.assertEqual(res,1)

if __name__ == '__main__':
    unittest.main()