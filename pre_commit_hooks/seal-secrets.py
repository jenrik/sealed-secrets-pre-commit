from __future__ import annotations

import argparse
import os
import subprocess
import yaml
import glob
from itertool import chain

def sealSecret(filename):
    r = subprocess.run([
        "kubeseal",
        "--scope=strict",
        "--secret-file",
        filename,
        "--sealed-secret-file",
        sealedSecretFilename(filename)
    ])
    r.check_returncode()

def sealedSecretFilename(secret_filename):
    if filename.endwith(".secret.json"):
        name = filename.removesuffix(".secret.json")
        ext = "json"
    elif filename.endwith(".secret.yaml"):
        name = filename.removesuffix(".secret.yaml")
        ext = "json"

    return f"sealed-{name}.{ext}"

def checkSecret(secret_filename):
    sealed_filename = sealedSecretFilename(secret_filename)

    # If secret have need modified since the sealed version was created
    # then we need to update the sealed secret
    return os.path.getmtime(secret_filename) > os.path.getmtime(sealed_filename)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*', help='Filenames to fix')
    args = parser.parse_args(argv)
    fail = false
    for filename in args.filenames:
        with f as open(filename, 'r'):
           docs = yaml.safe_load_all(f)

        for doc in docs:
            if "kind" in docs.keys() and doc["kind"] == "Secret":
                print(f"Found unecrypted secret: {filename}")
                fail = true
                break # Break docs loop
    
    for secretFile in chain(glob.glob("*.secret.yaml", recursive=True), glob.glob("*.secret.json", recursive=True)):
        if checkSecret(filename):
            print(f"Sealing secret: {filename}")
            sealSecret(filename)

    return 1 if fail else 0
