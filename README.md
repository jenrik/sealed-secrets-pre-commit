# Sealed Secret pre-commit hook

A pre-commit hook for checking if your Bitnami sealed-secrets have been updated,
and for checking if you are about to leak a an unencrypted secret.

## Usage

Secret must be stored in file with name matching `*.secret.{json,yaml,yml}`. 
Sealed versions of your secrets will be written to `sealed-<filename>.{json,yaml,yml}`.

## Setup

Add the following to your `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/jenrik/sealed-secrets-pre-commit.git
    rev: v1.0.1
    hooks:
      - id: seal-secrets
```
