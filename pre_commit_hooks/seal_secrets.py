from __future__ import annotations

from itertools import chain
import argparse
import glob
import os
import re
import subprocess
import yaml

def sealSecret(filename):
    sealed_filename = sealedSecretFilename(filename)
    #pre_mtime = 0
    #if os.path.exists(sealed_filename):
    #   pre_mtime = os.path.getmtime(sealed_filename)
    r = subprocess.run([
        "kubeseal",
        "--scope=strict",
        "--secret-file",
        filename,
        "--sealed-secret-file",
        sealed_filename
    ])
    r.check_returncode()
    #return pre_mtime != os.path.getmtime(sealed_filename)

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
    elif filename.endswith(".secret.yml"):
        name = filename.removesuffix(".secret.yml")
        ext = "yml"

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

    insecure_pattern = re.compile(r"\.insecure\.(ya?ml|json)$")

    for filename in args.filenames:
        if insecure_pattern.match(filename):
            # File is allowed to be unencrypted
            continue

        with open(filename, 'r') as f:
            try:
                for doc in yaml.safe_load_all(f):
                    if isinstance(doc, dict) and "kind" in doc.keys() and doc["kind"] == "Secret":
                        print(f"Found unecrypted secret: {filename}")
                        fail = True
                        break # Break docs loop
            except (yaml.scanner.ScannerError, yaml.parser.ParserError):
                pass
    
    find_pattern = lambda p: glob.glob("**/" + p, recursive=True, include_hidden=True)
    for filename in chain(find_pattern("*.secret.yaml"), find_pattern("*.secret.yml"), find_pattern("*.secret.json")):
        if checkSecret(filename):
            if filename not in args.filenames:
                fail = True
            sealSecret(filename)

    r = subprocess.run(["git", "ls-files", "--others", "--exclude-standard"], capture_output=True)
    r.check_returncode()
    for untracked in r.stdout.decode("utf-8").splitlines():
        basename = os.path.basename(untracked)
        if basename.startswith("sealed-") and (basename.endswith(".json") or basename.endswith(".yaml") or basename.endswith(".yml")):
            print("Please stage sealed secret: " + untracked)
            fail = True

    return 1 if fail else 0

if __name__ == '__main__':
    raise SystemExit(main())
