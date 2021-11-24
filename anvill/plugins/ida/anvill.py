#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

import ida_funcs
import ida_kernwin
import idautils

import anvill
import json

class generate_anvill_spec_t(ida_kernwin.action_handler_t):
  def activate(self, ctx):
    user_input = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, "Would you like to export all functions?")
    if user_input == ida_kernwin.ASKBTN_CANCEL:
      return 1

    output_file_name_hint = ""

    p = anvill.get_program()

    if user_input == ida_kernwin.ASKBTN_NO:
      screen_cursor = ida_kernwin.get_screen_ea()
      function_name = ida_funcs.get_func_name(screen_cursor)
      if function_name is None:
        print("anvill: The cursor is not located inside a function")
        return 1

      output_file_name_hint = function_name + ".json"

      try:
        p.add_function_definition(screen_cursor)

      except:
        print("anvill: Failed to process the function at address {0:x}".format(screen_cursor))
        return 1

    else:
      function_address_list = idautils.Functions()
      for function_address in function_address_list:
        try:
          p.add_function_definition(function_address)

        except:
          print("anvill: Failed to process the function at address {0:x}".format(function_address))

      output_file_name_hint = "program.json"

    output_path = ida_kernwin.ask_file(True, output_file_name_hint, "Select where to save the spec file")
    if not output_path:
      return 1

    output = json.dumps(p.proto(), sort_keys=False, indent=2)

    print("anvill: Saving the spec file to {}".format(output_path))
    with open(output_path, "w") as f:
      f.write(output)

  def update(self, ctx):
    if ctx.widget_type == ida_kernwin.BWN_DISASM:
      return ida_kernwin.AST_ENABLE_FOR_WIDGET

    return ida_kernwin.AST_DISABLE_FOR_WIDGET

ACTION_NAME = "generate-anvill-spec-file"

ida_kernwin.register_action(
    ida_kernwin.action_desc_t(
        ACTION_NAME,
        "Generate anvill spec file",
        generate_anvill_spec_t(),
        "Ctrl+H"))

class popup_hooks_t(ida_kernwin.UI_Hooks):
  def finish_populating_widget_popup(self, w, popup):
    if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_DISASM:
      ida_kernwin.attach_action_to_popup(w, popup, ACTION_NAME, None)

hooks = popup_hooks_t()
hooks.hook()
