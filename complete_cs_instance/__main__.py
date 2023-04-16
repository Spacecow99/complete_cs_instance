
import argparse
import re
import json
from collections import namedtuple

import sys

'''Derives related algorithms form instance.name of the cipher suites.'''
def complete_cs_instance(instance, *args, **kwargs):
    # SSLv2 ciphers
    if instance.hex_byte_3:
        name = instance.name.replace("_CK", "")
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (enc,_,hsh) = rst.rpartition("WITH")
        # Handle SSL_CK_NULL and SSL_CK_NULL_WITH_MD5
        if re.search("NULL", enc) or re.search("NULL", hsh):
            kex, aut = "NULL", "NULL"
            # Handle SSL_CK_NULL
            if not enc.strip():
                enc = "NULL"
        else:
            kex = "RSA"
            aut = "RSA"  

    # GOST TLSv1.2 ciphers
    elif (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x00') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x01') or\
        (instance.hex_byte_1 == '0xC1' and instance.hex_byte_2 == '0x02'):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition("WITH")
        prt = "TLS"
        kex = "GOSTR341012"
        aut = "GOSTR341012"
        hsh = "GOSTR341112"
        enc = rst

    # GOST TLSv1.3 ciphers
    elif (instance.hex_byte_1 == "0xC1" and instance.hex_byte_2 == "0x03") or\
        (instance.hex_byte_1 == "0xC1" and instance.hex_byte_2 == "0x04") or\
        (instance.hex_byte_1 == "0xC1" and instance.hex_byte_2 == "0x05") or\
        (instance.hex_byte_1 == "0xC1" and instance.hex_byte_2 == "0x06"):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition("WITH")
        prt = "TLS"
        kex = "-"
        aut = "-"
        enc = rst
        hsh = "GOSTR341112"

    # GOST R 34.10-94 and 34.10-01 28147_CNT_IMIT ciphers
    elif (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0x80") or\
        (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0x81"):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (kex,_,enc) = rst.partition("WITH")
        (kex,_,aut) = kex.partition(" ")
        hsh = "GOSTR341194"

    # GOST R 34.10-94 and 34.10-01 NULL ciphers
    elif (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0x82") or\
        (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0x83"):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (kex,_,enc) = rst.partition(" WITH ")
        (kex,_,aut) = kex.partition(" ")
        (enc,_,hsh) = enc.partition(" ")
        hsh = "GOSTR341194"

    # Parsing for TLS_RSA_WITH_28147_CNT_GOST94. The logic for TLS_GOSTR341094_RSA_WITH_28147_CNT_MD5
    # mirrors that of the else block bellow so we just let it roll through.
    elif (instance.hex_byte_1 == "0xFF" and instance.hex_byte_2 == "0x01"):
        name = instance.name
        prt = "TLS"
        kex = "RSA"
        aut = "RSA"
        enc = "28147 CNT"
        hsh = "GOSTR341194"

    # TLS1.3 authentication/integrity-only ciphers
    elif (instance.hex_byte_1 == '0xC0' and instance.hex_byte_2 == '0xB4') or\
        (instance.hex_byte_1 == '0xC0' and instance.hex_byte_2 == '0xB5'):
        name = instance.name
        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (aut,_,hsh) = rst.rpartition(" ")
        enc = "NULL"
        kex = "-"

    # TLS_EMPTY_RENEGOTIATION_INFO_SCSV and TLS_FALLBACK_SCSV extensions
    elif (instance.hex_byte_1 == "0x00" and instance.hex_byte_2 == "0xFF") or\
        (instance.hex_byte_1 == "0x56" and instance.hex_byte_2 == "0x00"):
        name = instance.name
        prt = "TLS"
        kex = aut = enc = hsh = "-"

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
	    # NOTE: New addition
        # OLD substring does not describe any algorithm, so we remove it
        # we don't do anything with it for the moment however that needs to change
        # OLD_ at the beginning seems to be the convention everywhere except TestSSL
        
        # NOTE: It appears everything under here may leave off the kex/auth algos
        #   might need to be moved to it's own section
        name = instance.name

        if re.search("OLD", name):
            name = name.replace('_OLD', '')
            name = name.replace('OLD_', '')
            old_cipher = True
        else:
            #name = instance.name
            old_cipher = False

        # EXPORT substring does not describe any algorithm, so we remove it
        # substring is later appended to the protocol_version
        if re.search("EXPORT", name):
            name = name.replace('EXPORT_', '')
            name = name.replace('EXPORT1024_', '')
            name = name.replace('EXPORT40', '')
            export_cipher = True
        else:
            #name = instance.name
            export_cipher = False

        if re.search("FIPS", name):
            name = name.replace('FIPS_', '')
            fips_cipher = True
        else:
            fips_cipher = False

        (prt,_,rst) = name.replace("_", " ").partition(" ")
        (kex,_,rst) = rst.partition("WITH")

        # add information about export-grade cipher to protocol version
        if export_cipher:
            prt += " EXPORT"

        # add information about OLD pre-IETF adopted status to protocol version
        if old_cipher:
            prt = "OLD " + prt

        # split kex again, potentially yielding auth algorithm
        # otherwise this variable will remain unchanged
        (kex,_,aut) = kex.partition(" ")
        (enc,_,hsh) = rst.rpartition(" ")

        # NOTE: In instances where FIPS is in ciphersuite name, append it to kex
        #  which is extremely likely to be RSA, thus both kex and auth
        if fips_cipher:
            kex += " FIPS"

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
    parser = argparse.ArgumentParser()
    parser.add_argument("JSON", help="JSON file of ciphersuites to test parsing against")
    args = parser.parse_args()

    ciphersuite = namedtuple("ciphersuite", ["name", "hex_byte_1", "hex_byte_2", "hex_byte_3"])

    with open(args.JSON, 'r') as f:
        j = json.load(f)
    rows = []
    for cipher in j:
        # Ignore 3rd byte for the moment
        hex = cipher["Value"].split(',')
        hex1 = hex[0]
        hex2 = hex[1]
        hex3 = hex[2] if len(hex) == 3 else None
        c = ciphersuite._make([cipher["Description"], hex1, hex2, hex3])
        parsed = complete_cs_instance(c)
        rows.append({"Value": cipher["Value"], "Description": cipher["Description"], **parsed})
    print(json.dumps(rows, indent=4))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(" ")
