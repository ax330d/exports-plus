#!c:\\python27\python.exe
# -*- coding: utf-8 -*-

"""
Exports+ IDA Pro plugin -- demangles names where needed and replaces empty
names.
"""

import idaapi
import idc
import idautils
from idaapi import Choose2


__author__ = 'Arthur Gerkis'
__version__ = '0.0.1'


class ExportChooser(Choose2):
    """ExportChooser creates a new window in IDA."""
    def __init__(self, title, items):
        Choose2.__init__(self,
                         title,
                         [["Name", 60], ["Address", 10], ["Ordinal", 10], ["Original Name", 60]],
                         embedded=False)
        self.items = items
        self.icon = 135

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        idaapi.jumpto(int(self.items[n][1], 16))


class ExportsPlus(object):
    """ExportsRenamer class."""

    def __init__(self):
        return

    def run(self):
        """Run."""
        exports = list(idautils.Entries())

        new_exports = []
        for exp_i, exp_ord, exp_ea, exp_name in exports:
            orig_exp_name = exp_name
            if not exp_name:
                exp_name = idc.GetFunctionName(exp_ea)
                if not exp_name:
                    exp_name = '(error: unable to resolve)'
            if exp_ea == exp_ord:
                exp_ord = '[main entry]'
            new_exports.append([self.demangle(exp_name), "%08X" % exp_ea, "%s" % exp_ord, orig_exp_name])

        ExportChooser("Exports+", new_exports).Show()
        return

    def demangle(self, name):
        """Demangle name."""
        mask = idc.GetLongPrm(idc.INF_SHORT_DN)
        demangled = idc.Demangle(name, mask)
        if demangled is None:
            return name
        return demangled


def main():
    """Main entry."""

    expp = ExportsPlus()
    expp.run()


if __name__ == "__main__":
    main()
