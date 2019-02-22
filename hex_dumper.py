#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Check this out http://code.activestate.com/recipes/510399-byte-to-hex-and-hex-to-byte-string-conversion/
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Input file")
    parser.add_argument("-o", "--output", help="Directs the output hex dump to a file")
    return parser.parse_args()


def read_bytes(filename, chunk_size=8192):
    with filename as f:
        while True:
            chunk = f.read(chunk_size)
            if chunk:
                for b in chunk:
                    yield b
            else:
                break


# Loop through the given file while printing the address, hex and ascii output
def gen_data_list(bytes_data):
    data_as_list = []
    for byte in bytes_data:
        data_as_list.append(byte.encode('hex'))
    print('Generated data list')
    return data_as_list


def define_executable_type(data_list):
    magic_bytes = {'4D5A': 'DOS MZ executable file format and its descendants (including NE and PE)',
                   '7F454C46': 'Executable and Linkable Format'}
    print('[*] Detecting magic...')
    data_string = ''.join(data_list).upper()
    for magic_byte in magic_bytes:
        entry_bytes = data_string[0:len(magic_byte)]
        if magic_byte == entry_bytes:
            print('[+] Detected file type: ' + magic_bytes.get(magic_byte) + '\n')
            break
        else:
            print('[!] Did not find signatures for ' + magic_bytes.get(magic_byte) + ' in ' + entry_bytes)
    return data_string


def read_input_file():
    arguments = parse_args()
    try:
        file_contents = read_bytes(open(arguments.file, "rb"))
        return file_contents
    except IOError:
        print("\nError - The file provided does not exist\n"), exit(1)


def output(ar, data):
    if ar.output is not None:
        try:
            with open(ar.output, 'w') as output_file:
                output_file.write("%s\n" % data)
        except TypeError:
            pass  # Whatever
    else:
        print("Printing to stdout\n")
        print(data)


def main():
    args = parse_args()
    print('\n~~~~~ Dumping %s as HEX ~~~~~\n' % args.file)
    bytes_data = read_input_file()
    data_list = gen_data_list(bytes_data)
    data_str = define_executable_type(data_list)
    output(args, data_str)


main()
