import argparse
from bs4 import BeautifulSoup
import json

float_type_dict = {2: "e", 4: "f", 8: "F", 10: "d", 12: "D"}

integer_type_dict = {1: "c", 2: "h", 4: "i", 8: "l", 16: "o"}


def generate_type_from_size(sz, is_float):
    if sz == 0:
        return "v"

    if is_float and sz in float_type_dict:
        return float_type_dict[sz]

    if sz in integer_type_dict:
        return integer_type_dict[sz]

    return "{" + "p"*sz + "}"


def trim_reg_name(nm):
    return nm.split('_Qa')[0]


def translate_reg(pentry, reg, is_float):
    obj = {}
    obj['register'] = trim_reg_name(reg['name'])
    obj['type'] = generate_type_from_size(int(pentry['maxsize']), is_float)
    return obj


def translate_pentry(pentry):
    reg = pentry.find("register")
    is_float = "metatype" in pentry.attrs and pentry["metatype"] == "float"

    if reg is not None:
        return translate_reg(pentry, reg, is_float)


def translate_pentry_list(pentries):
    return list(filter(lambda x: x is not None, map(translate_pentry, pentries.find_all("pentry"))))


def translate_outputs_to_returns(outputs):
    return translate_pentry_list(outputs)


def translate_inputs_to_parameters(inputs):
    return translate_pentry_list(inputs)


def translate_return_address(ret_addr, stack_reg, ptr_sz):
    if ret_addr is not None:
        if ret_addr.register is not None:
            return {"register": ret_addr.name, "type": generate_type_from_size(ptr_sz, False)}

        if ret_addr.find(space='stack') is not None:
            stack_varnode = ret_addr.find(space='stack')
            return {"memory": {"register": stack_reg,
                               "offset": int(stack_varnode['offset'])}, "type": generate_type_from_size(int(stack_varnode['size']), False)}
    else:
        return {"memory": {"register": stack_reg, "offset": 0}, "type": generate_type_from_size(ptr_sz, False)}


def main(target_input, target_output):
    with open(target_input, 'r') as f:
        with open(target_output, 'w') as out_f:
            soup = BeautifulSoup(f, 'xml')
            target_proto = soup.default_proto.prototype
            pointer_size = int(soup.data_organization.pointer_size['value'])

            func = {}
            func['is_noreturn'] = False
            func['calling_convention'] = 0
            func['is_variadic'] = False
            func['parameters'] = translate_inputs_to_parameters(target_proto.input)
            func['return_values'] = translate_outputs_to_returns(
                target_proto.output)

            return_reg = {}
            return_reg['register'] = soup.stackpointer['register']
            return_reg['offset'] = 0
            return_reg['type'] = generate_type_from_size(pointer_size, False)
            func['return_address'] = translate_return_address(
                soup.returnaddress, soup.stackpointer['register'], pointer_size)
            func['return_stack_pointer'] = return_reg
            json.dump(func, out_f, indent=4, sort_keys=True)


if __name__ == "__main__":
    arg_parse = argparse.ArgumentParser(
        "Translates cspec default prototypes into json specs")
    arg_parse.add_argument("target_input")
    arg_parse.add_argument("target_output")

    args = arg_parse.parse_args()
    main(args.target_input, args.target_output)
