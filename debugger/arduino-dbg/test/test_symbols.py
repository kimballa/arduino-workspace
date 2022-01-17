#!/usr/bin/env python3
# (c) Copyright 2022 Aaron Kimball

import unittest

import arduino_dbg.types as types
from dbg_testcase import *

class TestSymbols(DbgTestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

    @classmethod
    def getDumpFilename(cls):
        # Dump captured at breakpoint immediately before __user_setup().
        return "fixtures/startup.dump"

    def test_all_syms(self):
        all_syms = self.debugger.syms_by_substr("")
        self.assertIsInstance(all_syms, list)
        self.assertGreater(len(all_syms), 0)

    def test_sym_substr(self):
        twi_syms = self.debugger.syms_by_substr("twi_")
        self.assertIsInstance(twi_syms, list)
        self.assertEqual(len(twi_syms), 22) # core defines 22 twi_* methods


    def test_c_func_datatype(self):
        (kind, typ) = self._get_datatype_for("twi_init")
        self.assertEqual(kind, types.KIND_METHOD)
        self.assertEqual(str(typ), 'public void twi_init()')

    def test_typedef(self):
        (kind, typ) = self._get_datatype_for("uint8_t")
        self.assertEqual(kind, types.KIND_TYPE)
        self.assertEqual(str(typ), 'typedef unsigned char uint8_t')

    def test_global_var_datatype(self):
        (kind, typ) = self._get_datatype_for("debug_status")
        self.assertEqual(kind, types.KIND_VARIABLE)
        self.assertEqual(typ.var_name, 'debug_status')
        self.assertEqual(typ.var_type.name, 'uint8_t')

if __name__ == "__main__":
    unittest.main(verbosity=2)
