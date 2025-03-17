from __future__ import annotations

import argparse
import os
import subprocess
import yaml
import glob
from itertools import chain

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
    name = None
    ext = None
    filename = os.path.basename(secret_filename)
    if filename.endswith(".secret.json"):
        name = filename.removesuffix(".secret.json")
        ext = "json"
    elif filename.endswith(".secret.yaml"):
        name = filename.removesuffix(".secret.yaml")
        ext = "yaml"

    return os.path.join(
        os.path.dirname(secret_filename),
        f"sealed-{name}.{ext}"
    )

def checkSecret(secret_filename):
    sealed_filename = sealedSecretFilename(secret_filename)

    # If secret have need modified since the sealed version was created
    # then we need to update the sealed secret
    if not os.path.isfile(sealed_filename):
        return True
    else:
        return os.path.getmtime(secret_filename) > os.path.getmtime(sealed_filename)

def main(argv = None):
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*', help='Filenames to fix')
    args = parser.parse_args(argv)
    fail = False
    for filename in args.filenames:
        with open(filename, 'r') as f:
           docs = yaml.safe_load_all(f)

           for doc in docs:
               if "kind" in doc.keys() and doc["kind"] == "Secret":
                   print(f"Found unecrypted secret: {filename}")
                   fail = True
                   break # Break docs loop
    
    find_pattern = lambda p: glob.glob("**/" + p, recursive=True, include_hidden=True)
    for filename in chain(find_pattern("*.secret.yaml"), find_pattern("*.secret.json")):
        if checkSecret(filename):
            print(f"Sealing secret: {filename}")
            sealSecret(filename)

    return 1 if fail else 0

if __name__ == '__main__':
    raise SystemExit(main())
