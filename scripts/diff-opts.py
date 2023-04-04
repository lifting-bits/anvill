import argparse
import tempfile
import re
import subprocess

# use with `-llvm_print_all_before -llvm_print_all_after` flags
# Adapted from: https://gist.github.com/porglezomp/f2dc233f971cf3f30d45e0b501ae5ead

def run_diff(name, before, after):
    if info_match := re.search("define [^ ]+ @func([0-9]+)basic_block([0-9]+)", before[1]):
        func_addr = int(info_match[1])
        bb_addr = int(info_match[2])
        print(f"Function address: {func_addr:x} BB addrs: {bb_addr:x}")

    before = '\n'.join(b.rstrip() for b in before).strip()
    after = '\n'.join(a.rstrip() for a in after).strip()
    with tempfile.NamedTemporaryFile() as b, tempfile.NamedTemporaryFile() as a:
        b.write(before.encode())
        a.write(after.encode())
        b.flush()
        a.flush()
        result = subprocess.run(['icdiff', '-W', b.name, a.name], stdout=subprocess.PIPE)
        print(f"Step: {name}")
        if result.stdout:
            print(result.stdout.decode())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=argparse.FileType("r"))
    args = parser.parse_args()

    with args.file as f:
        result = f.read()
    lines = result.split('\n')
    name = None
    before = []
    after = []
    is_before = None
    for line in lines:
        if line.startswith('*** IR Dump After'):
            is_before = False
        elif line.startswith('*** IR Dump Before'):
            name_match = re.search("\\(([^\\)]+)\\)", line)
            if name_match:
                name = name_match.group(1)
            if len(before) > 0 and len(after) > 0:
                run_diff(name, before, after)
                before = []
                after = []
            is_before = True
        else:
            if is_before:
                before.append(line)
            else:
                after.append(line)

    run_diff(name, before, after)

if __name__ == '__main__':
    main()
