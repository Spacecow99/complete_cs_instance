
import argparse
import re
import json
from collections import namedtuple

import sys
import yaml

from complete_cs_instance import complete_cs_instance


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("JSON", help="JSON file of ciphersuites to test parsing against")
    args = parser.parse_args()

    ciphersuite = namedtuple("ciphersuite", ["name", "hex_byte_1", "hex_byte_2", "hex_byte_3"])

    with open(args.JSON, 'r') as f:
        y = yaml.safe_load(f)

    rows = []
    for cipher in y:
        hex1 = cipher.get("fields", {}).get("hex_byte_1")
        hex2 = cipher.get("fields", {}).get("hex_byte_2")
        hex3 = cipher.get("fields", {}).get("hex_byte_3", None)
        c = ciphersuite._make([cipher["pk"], hex1, hex2, hex3])
        parsed = complete_cs_instance(c)
        hexcode = f"{hex1},{hex2}{','+hex3 if hex3 else ''}"
        rows.append({"Value": hexcode, "Description": cipher["pk"], **parsed})
    
    print(yaml.dump(rows, sort_keys=False))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(" ")
