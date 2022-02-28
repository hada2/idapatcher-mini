#!/usr/bin/env python
#
# IDA Patcher (Mini) is a ported version of IDA Patcher to IDA Pro 7.7.
# This is a plugin for Hex-Ray's IDA Pro disassembler designed to
# enhance IDA's ability to patch binary files and memory. The plugin is
# useful for tasks related to malware analysis, exploit development as well
# as bug patching. IDA Patcher blends into the standard IDA user interface
# through the addition of a subview and several menu items.

IDAPATCHERMINI_VERSION = "1.3"

# Copyright (C) 2014 Peter Kacherginsky
# Copyright (C) 2022 Hiroki Hada
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# IDA libraries
import idaapi
import idautils
import idc
from idaapi import Form, plugin_t

# Python modules
import os
import binascii


#--------------------------------------------------------------------------
# Forms
#--------------------------------------------------------------------------

class PatchEditForm(Form):
    """
    Form to edit patched bytes.
    """
    def __init__(self, addr_str, fpos_str, patch_str, org_str):
        Form.__init__(self,
r"""Edit patch bytes

Address        {strAddr}
File offset    {strFpos}
<:{strPatch}>
""", {
        'strAddr':  Form.StringLabel(addr_str),
        'strFpos':  Form.StringLabel(fpos_str),
        'strPatch': Form.MultiLineTextControl(text=patch_str, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT),
        })

        self.Compile()


#--------------------------------------------------------------------------

class PatchFillForm(Form):
    """
    Form to fill a range of addresses with a specified byte value.
    """
    def __init__(self, start_ea, end_ea, fill_value):

        Form.__init__(self,
r"""BUTTON YES* Fill
Fill bytes

<##Start EA   :{intStartEA}>
<##End EA     :{intEndEA}>
<##Value      :{intPatch}>
""", {
        'intStartEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=start_ea),
        'intEndEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=end_ea),
        'intPatch': Form.NumericInput(swidth=40,tp=Form.FT_HEX,value=fill_value),
        })

        self.Compile()


#--------------------------------------------------------------------------

class DataImportForm(Form):
    """
    Form to import data of various types into selected area.
    """
    def __init__(self, start_ea, end_ea):
        Form.__init__(self,
r"""BUTTON YES* Import
Import data

{FormChangeCb}
<##Start EA   :{intStartEA}>
<##End EA     :{intEndEA}>

Import type:                    Patching options:
<hex string:{rHex}><##Trim to selection:{cSize}>{cGroup}>
<string literal:{rString}>
<binary file:{rFile}>{rGroup}>

<:{strPatch}>
<##Import BIN file:{impFile}>
""", {
        'intStartEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=start_ea),
        'intEndEA': Form.NumericInput(swidth=40,tp=Form.FT_ADDR,value=end_ea),

        'cGroup': Form.ChkGroupControl(("cSize",)),
        'rGroup': Form.RadGroupControl(("rHex", "rString", "rFile")),

        'strPatch': Form.MultiLineTextControl(swidth=80, flags=Form.MultiLineTextControl.TXTF_FIXEDFONT),
        'impFile': Form.FileInput(swidth=50, open=True),

        'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })

        self.Compile()

    def OnFormChange(self, fid):
        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.strPatch)
            self.EnableField(self.strPatch, True)
            self.EnableField(self.impFile, False)

        # Form OK pressed
        elif fid == -2:
            pass

        # Form from text box
        elif fid == self.rHex.id or fid == self.rString.id:
            self.SetFocusedField(self.strPatch)
            self.EnableField(self.strPatch, True)
            self.EnableField(self.impFile, False)

        # Form import from file
        elif fid == self.rFile.id:
            self.SetFocusedField(self.rFile)
            self.EnableField(self.impFile, True)
            self.EnableField(self.strPatch, False)

        return 1


#--------------------------------------------------------------------------
# Manager
#--------------------------------------------------------------------------

class PatchManager_ah_t(idaapi.action_handler_t):
    def __init__(self, cb):
        idaapi.action_handler_t.__init__(self)
        self.cb = cb

    def activate(self, ctx):
        self.cb()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class PatchManager():
    """ Class that manages GUI forms and patching methods of the plugin. """

    def __init__(self):
        self.addmenu_item_ctxs = list()

    #--------------------------------------------------------------------------
    # Menu Items
    #--------------------------------------------------------------------------
    def add_menu_item_helper(self, menupath, name, hotkey, flags, pyfunc, args):
        addmenu_item_ctx = None

        # add menu item and report on errors
        if idaapi.IDA_SDK_VERSION >= 700:
            action_name = name.strip(".")
            action_label = name
            action_qname = "IDAPatcher:%s" % action_name
            action_desc = idaapi.action_desc_t(
                action_qname,
                action_label,
                PatchManager_ah_t(pyfunc),
                hotkey
            )

            if idaapi.register_action(action_desc):
                addmenu_item_ctx = idaapi.attach_action_to_menu(menupath, action_qname, idaapi.SETMENU_APP)

        else:
            addmenu_item_ctx = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)

        if addmenu_item_ctx is None:
            return 1
        else:
            self.addmenu_item_ctxs.append(addmenu_item_ctx)
            return 0

    def add_menu_items(self):
        if self.add_menu_item_helper("Edit/Patch program/", "Edit selection...", "Alt+Shift+E", 0, self.show_edit_form, None):  return 1
        if self.add_menu_item_helper("Edit/Patch program/", "Fill selection...", "Alt+Shift+F", 0, self.show_fill_form, None):  return 1
        if self.add_menu_item_helper("Edit/Export data...", "Import data...", "Shift+I", 1, self.show_import_form, None):   return 1
        return 0

    def del_menu_items(self):
        for addmenu_item_ctx in self.addmenu_item_ctxs:
            # idaapi.del_menu_item(addmenu_item_ctx)
            pass

    #--------------------------------------------------------------------------
    # View Callbacks
    #--------------------------------------------------------------------------

    # Patches Edit Dialog
    def show_edit_form(self):
        view = idaapi.get_current_viewer()
        t0, t1 = idaapi.twinpos_t(), idaapi.twinpos_t()

        if idaapi.read_selection(view, t0, t1):
            start_ea, end_ea = t0.place(view).toea(), t1.place(view).toea()
        else:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1

        buf_len = end_ea - start_ea
        buf = idaapi.get_bytes(start_ea, buf_len) or "\xFF"*buf_len
        buf_str = " ".join(["%02X" % x for x in buf])

        fpos = idaapi.get_fileregion_offset(start_ea)

        addr_str = "%#X" % start_ea
        fpos_str = "%#x" % fpos if fpos != -1 else "N/A"

        f = PatchEditForm(addr_str, fpos_str, buf_str, buf_str)

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            # Convert hex bytes to binary
            buf = f.strPatch.value
            buf = buf.replace(' ','')       # remove spaces
            buf = buf.replace('\\x','')     # remove '\x' prefixes
            buf = buf.replace('0x','')      # remove '0x' prefixes
            buf = buf.replace('\n','')
            try:
                buf = binascii.unhexlify(buf)   # convert to bytes
            except Exception as e:
                idaapi.warning("Invalid input: %s" % e)
                f.Free()
                return

            # Now apply newly patched bytes
            idaapi.patch_bytes(start_ea, buf)

        # Dispose the form
        f.Free()

    # Fill range with a value form
    def show_fill_form(self):
        view = idaapi.get_current_viewer()
        t0, t1 = idaapi.twinpos_t(), idaapi.twinpos_t()

        if idaapi.read_selection(view, t0, t1):
            start_ea, end_ea = t0.place(view).toea(), t1.place(view).toea()
        else:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1

        # Default fill value
        fill_value = 0x00

        # Create the form
        f = PatchFillForm(start_ea, end_ea, fill_value)

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            # Get updated values
            start_ea = f.intStartEA.value
            end_ea = f.intEndEA.value
            fill_value = f.intPatch.value

            # Now apply newly patched bytes
            # NOTE: fill_value is expected to be one byte
            #       so if a user provides a larger patch_byte()
            #       will trim the value as expected.

            for ea in range(start_ea, end_ea):
                idaapi.patch_byte(ea, fill_value)

        # Dispose the form
        f.Free()

    # Import data form
    def show_import_form(self):
        view = idaapi.get_current_viewer()
        t0, t1 = idaapi.twinpos_t(), idaapi.twinpos_t()

        if idaapi.read_selection(view, t0, t1):
            start_ea, end_ea = t0.place(view).toea(), t1.place(view).toea()
        else:
            start_ea = idaapi.get_screen_ea()
            end_ea = start_ea + 1

        # Create the form
        f = DataImportForm(start_ea, end_ea);

        # Execute the form
        ok = f.Execute()
        if ok == 1:

            start_ea = f.intStartEA.value
            end_ea = f.intEndEA.value

            if f.rFile.selected:
                imp_file = f.impFile.value

                try:
                    f_imp_file = open(imp_file,'rb')
                except Exception as e:
                    idaapi.warning("File I/O error({0}): {1}".format(e.errno, e.strerror))
                    return
                else:
                    buf = f_imp_file.read()
                    f_imp_file.close()

            else:

                buf = f.strPatch.value

                # Hex values, unlike string literal, needs additional processing
                if f.rHex.selected:
                    buf = buf.replace(' ','')       # remove spaces
                    buf = buf.replace('\\x','')     # remove '\x' prefixes
                    buf = buf.replace('0x','')      # remove '0x' prefixes
                    buf = buf.replace('\n','')
                    try:
                        buf = binascii.unhexlify(buf)   # convert to bytes
                    except Exception as e:
                        idaapi.warning("Invalid input: %s" % e)
                        f.Free()
                        return

            if not len(buf):
                idaapi.warning("There was nothing to import.")
                return

            # Trim to selection if needed:
            if f.cSize.checked:
                buf_size = end_ea - start_ea
                buf = buf[0:buf_size]

            # Now apply newly patched bytes
            idaapi.patch_bytes(start_ea, buf)

        # Dispose the form
        f.Free()


#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class idapatcher_t(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "Enhances manipulation and application of patched bytes."
    help = "Enhances manipulation and application of patched bytes."
    wanted_name = "IDA Patcher (Mini)"
    wanted_hotkey = ""

    def init(self):
        global idapatcher_manager

        # Check if already initialized
        if not 'idapatcher_manager' in globals():

            idapatcher_manager = PatchManager()
            if idapatcher_manager.add_menu_items():
                print("Failed to initialize IDA Patcher (Mini).")
                idapatcher_manager.del_menu_items()
                del idapatcher_manager
                return idaapi.PLUGIN_SKIP
            else:
                print(("Initialized IDA Patcher (Mini)  v%s (c) Peter Kacherginsky <iphelix@thesprawl.org>, Hiroki Hada" % IDAPATCHERMINI_VERSION))

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global idapatcher_manager

    def term(self):
        pass


def PLUGIN_ENTRY():
    return idapatcher_t()

#--------------------------------------------------------------------------
# Script / Testing
#--------------------------------------------------------------------------
def idapatcher_main():
    global idapatcher_manager

    if 'idapatcher_manager' in globals():
        idapatcher_manager.del_menu_items()
        del idapatcher_manager

    idapatcher_manager = PatchManager()
    idapatcher_manager.add_menu_items()

if __name__ == '__main__':
    #idapatcher_main()
    pass

