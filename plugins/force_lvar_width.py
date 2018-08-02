""" Forcibly change the width of an lvar.
Useful for making an lvar smaller (which Hex-Rays does not let you do apparently)
Tags (for search engines):
IDA Pro Hex-Rays make stack variable smaller force variable size decrease width delete variable split up break up variable into smaller
"""

import idautils
import idaapi
import idc
import ida_hexrays

import traceback

force_width_actname = "forcelvarwidth:forcewidth"

class force_width_action_handler_t(idaapi.action_handler_t):
    def __init__(self, callback_info):
        idaapi.action_handler_t.__init__(self)
        self.callback_info = callback_info

    def activate(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        self.callback_info.gui_action_callback(vdui)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == idaapi.BWN_PSEUDOCODE else \
            idaapi.AST_DISABLE_FOR_WIDGET


class hexrays_callback_info(object):

    def __init__(self):
        self.vu = None
        return

    def load(self):
        return

    def save(self):
        return

    def do_force_width(self, cfunc, insn):

        if insn.opname != 'if':
            return False

        cif = insn.details

        if not cif.ithen or not cif.ielse:
            return False

        idaapi.qswap(cif.ithen, cif.ielse)
        cond = idaapi.cexpr_t(cif.expr)
        notcond = idaapi.lnot(cond)

        cif.expr.swap(notcond)

        return True

    def gui_action_callback(self, vu):

        cfunc = vu.cfunc.__deref__()
        
        if not vu.get_current_item(idaapi.USE_KEYBOARD):
            print "Force lvar width: you don't have anything selected"
            return False
            
        badlv = vu.item.get_lvar()
        if not badlv:
            print "Force lvar width: you don't have an lvar selected"
            return False

        new_width = idc.AskLong(badlv.width, "Enter the new width for " + badlv.name)
        if new_width == None: # cancelled
            print "Force lvar width: operation cancelled"
            return False

        if new_width <= 0:
            print "Force lvar width: not allowed. Non-positive width will crash IDA"
            return False

        badlv.set_width(new_width)
        print 'Set the type in IDA (Y) for it to apply'
        idaapi.process_ui_action('hx:SetType')

        # vu.refresh_ctext()
        print 'Force lvar width: OK.'
        return True

    def event_callback(self, event, *args):

        if event == idaapi.hxe_populating_popup:
            widget, phandle, vu = args
            res = idaapi.attach_action_to_popup(vu.ct, None, force_width_actname)

        return 0

class ForceLvarWidth(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    wanted_hotkey = "Shift-W"
    comment = "Force lvar width plugin for Hex-Rays decompiler"
    help = "There is no one to help you now"
    wanted_name = "Hex-Rays lvar width forcer"

    def init(self):
        if idaapi.init_hexrays_plugin():
            i = hexrays_callback_info()
            idaapi.register_action(
                idaapi.action_desc_t(
                    force_width_actname,
                    "Force lvar width",
                    force_width_action_handler_t(i),
                    "Shift-W"))
            idaapi.install_hexrays_callback(i.event_callback)
            print 'Hex-Rays lvar width forcer by ecx86 loaded!'
        else:
            print 'Force lvar width: Hexrays is not available.'

    def term(self):
        pass

    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return ForceLvarWidth()
