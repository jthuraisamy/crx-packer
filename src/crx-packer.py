#-------------------------------------------------------------------------------
# Name:        Command-line CRX Packer
# Purpose:     Pack Google Chrome extensions on the command line.
#
# Author:      jthuraisamy
# Created:     2013-11-01
#-------------------------------------------------------------------------------
#!/usr/bin/env python

# Import internal modules.
import os
import struct
import zipfile
import subprocess
from argparse import ArgumentParser

class CRX(object):
    def __init__(self, input_dir, key_file, output_file):
        self.input_dir = os.path.normpath(input_dir)
        self.key_file = os.path.normpath(key_file)
        self.output_file = os.path.normpath(output_file)
        self.zip_file = '%s.zip' % self.output_file

    def _run_process(self, cmd_line):
        return subprocess.Popen(cmd_line, stdout=subprocess.PIPE).stdout.read()

    def pack(self):
        # Zip input directory.
        with zipfile.ZipFile(self.zip_file, 'w') as zip_hnd:
            for directory in os.walk(self.input_dir):
                current_dir = directory[0]
                for filename in directory[2]:
                    file_path = os.path.join(current_dir, filename)
                    zip_path = os.path.join(os.path.relpath(current_dir,
                        self.input_dir), filename)
                    zip_hnd.write(file_path, zip_path, zipfile.ZIP_DEFLATED)
        # Generate public key from private key in key_file.
        pub_key = self._run_process(["openssl", "rsa", "-pubout", "-inform",
            "PEM", "-outform", "DER", "-in", self.key_file.replace('\\', '/')])
        # Sign zip_file with the key_file in PEM format.
        signature = self._run_process(["openssl", "sha1", "-sign",
            self.key_file.replace('\\', '/'),
            self.zip_file.replace('\\', '/')])
        # Generate header.
        magic_number = 'Cr24'
        version = struct.pack("<I", 2)
        pub_key_len = struct.pack("<I", len(pub_key))
        signature_len = struct.pack("<I", len(signature))
        # Write data to CRX file.
        with open(self.output_file, 'wb') as crx:
            crx.write(magic_number)
            crx.write(version)
            crx.write(pub_key_len)
            crx.write(signature_len)
            crx.write(pub_key)
            crx.write(signature)
            with open(self.zip_file, 'rb') as zip_file:
                crx.write(zip_file.read())
        # Delete intermediary zip.
        os.remove(self.zip_file)

def main():
    # Parse arguments.
    parser = ArgumentParser(description='CRX Packer by jthuraisamy (2013)')
    parser.add_argument('--dir', required=True, help='Extension Directory')
    parser.add_argument('--key', required=True, help='Private Key (PEM file)')
    parser.add_argument('--crx', required=True, help='Output CRX')
    args = parser.parse_args()
    # Initialise CRX.
    crx = CRX(args.dir, args.key, args.crx)
    # Pack CRX.
    crx.pack()

if __name__ == '__main__':
    main()
