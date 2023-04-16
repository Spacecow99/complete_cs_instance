#!/usr/bin/env python3

"""
CLI application entry point for complete_cs_instance.

A pyproject compliant cookiecutter template for Python packages.
"""

import argparse
from collections import namedtuple
import json
import re
import sys

from complete_cs_instance import __version__


def complete_cs_instance(instance, *args, **kwargs):
    '''Derives related algorithms form instance.name of the cipher suites.'''

    # GOST ciphers
    if (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x01') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x02') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x03'):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition("WITH")
        (enc,_,aut) = rst.rpartition(" ")
        prt = "TLS"
        kex = "VKO GOSTR3410 2012 256"
        hsh = "GOST R 34.11-2012"

    # TLS1.3 authentication/integrity-only ciphers
    elif (instance.hex_byte_1 == '0xC0' and instance.hex_byte_2 == '0xB4') or\
        (instance.hex_byte_1 == '0xC0' and instance.hex_byte_2 == '0xB5'):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (aut,_,hsh) = rst.rpartition(" ")
        enc = "NULL"
        kex = "-"

    # TLS1.3 ciphers
    elif instance.hex_byte_1 == '0x13'\
        or instance.hex_byte_2 == '0xC6'\
        or instance.hex_byte_2 == '0xC7':
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (enc,_,hsh) = rst.rpartition(" ")
        aut = "-"
        kex = "-"

    else:
        # EXPORT substring does not describe any algorithm, so we remove it
        # substring is later appended to the protocol_version
        if re.search("EXPORT", instance.name):
            name = instance.name.replace('EXPORT_', '')
            export_cipher = True
        else:
            name = instance.name
            export_cipher = False

        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (kex,_,rst) = rst.partition("WITH")

        # add information about export-grade cipher to protocol version
        if export_cipher:
            prt += " EXPORT"

        # split kex again, potentially yielding auth algorithm
        # otherwise this variable will remain unchanged
        (kex,_,aut) = kex.partition(" ")
        (enc,_,hsh) = rst.rpartition(" ")

        # split enc again if we only got a number for hsh
        # specifically needed for CCM/CCM8 ciphers
        if re.match(r'\d+', hsh.strip()) or re.match(r'CCM\Z', hsh.strip()):
            enc += " " + hsh
            hsh = "SHA256"

        if kex.strip() == "PSK" and aut.strip() == "DHE":
            kex = "DHE"
            aut = "PSK"

    # identify AEAD algorithms
    aead_flag = False
    if re.search(r'GCM|POLY1305|CCM|MGM', enc, re.IGNORECASE):
        aead_flag = True
    
    # Substitute a dict for the ciphersuite model
    parsed = {}

    # connect foreign keys from other models
    # if aut is not excplicitly defined, set it equal to kex
    if not aut:
        parsed["AuthAlgorithm"]=kex.strip()
    else:
        parsed["AuthAlgorithm"]=aut.strip()

    parsed["KexAlgorithm"]=kex.strip()
    parsed["ProtocolVersion"]=prt.strip()
    parsed["HashAlgorithm"]=hsh.strip()

    parsed["EncAlgorithm"]=enc.strip()
    parsed["aead_algorithm"] = aead_flag

    return parsed


def main():
    parser = argparse.ArgumentParser(prog="complete_cs_instance")
    parser.add_argument("JSON", help="JSON file of ciphersuites to test parsing against")
    parser.add_argument("--version", action="version", version=f"{__version__}")
    args = parser.parse_args()

    ciphersuite = namedtuple("ciphersuite", ["name", "hex_byte_1", "hex_byte_2", "hex_byte_3"])

    with open(args.JSON, 'r') as f:
        j = json.load(f)

    rows = []
    for cipher in j:
        # Ignore 3rd byte for the moment
        hex = cipher["Value"].split(',')
        hex1, hex2, hex3 = hex[0], hex[1], hex[2] if len(hex) == 3 else None
        c = ciphersuite._make([cipher["Description"], hex1, hex2, hex3])
        parsed = complete_cs_instance(c)
        rows.append({
            "Value": cipher["Value"],
            "Description": cipher["Description"],
            **parsed
        })
   
    print(json.dumps(rows, indent=4))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")

