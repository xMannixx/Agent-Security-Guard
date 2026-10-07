"""Credential formats and look-alikes, shared by the scanner, threat and
availability tests.

The values are assembled from pieces so that no line of this file is itself a
credential-shaped string: none of them was ever valid, and a secret scanner
reading the repository should not have to be told so.
"""

import base64
import json


def _b64(obj) -> str:
    raw = json.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


JWT = ".".join([
    _b64({"alg": "HS256", "typ": "JWT"}),
    _b64({"sub": "1234567890", "name": "A. User"}),
    "s" * 43,
])
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
_VALUE = "A1b2C3d4E5" + "f6G7h8J9k0"
_DB_PASSWORD = "s3cr3t" + "Pw9"

# Formats the scanner did not recognize before. name -> text containing one.
SECRET_SAMPLES = {
    "quoted api_key": '{"api_key": "%s"}' % _VALUE,
    "quoted secret_key, single quotes": "{'secret_key': '%s'}" % _VALUE,
    "quoted access_token, no space": '{"access_token":"ya29.%s"}' % _VALUE,
    "quoted password": '{"user": "app", "password": "hunter2' + 'hunter2"}',
    "aws secret access key, env": "AWS_SECRET_ACCESS_KEY=" + AWS_SECRET,
    "aws secret access key, json": '"aws_secret_access_key": "%s"' % AWS_SECRET,
    "anthropic key": "sk-" + "ant-api03-" + "aB3_-" * 19,
    "openai project key": "sk-" + "proj-" + "aB3_x" * 10,
    "jwt": JWT,
    "gitlab token": "glpat" + "-" + "aB3dE6gH9jK2mN5pQ8sT",
    "github fine-grained token": "github" + "_pat_" + "11ABCDEFG0" + "a1B2c3D4e5" * 6,
    "postgres url": "postgres://app:%s@db.internal:5432/prod" % _DB_PASSWORD,
    "sqlalchemy url": "postgresql+psycopg2://app:%s@db.internal/prod" % _DB_PASSWORD,
    "mongodb srv url": "mongodb+srv://admin:%s@cluster0.abcde.mongodb.net/t" % _DB_PASSWORD,
    "redis url without a user": "redis://:%s@cache.internal:6379/0" % _DB_PASSWORD,
    "encrypted private key": "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----",
    "pgp private key": "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----",
}

# Text that names or resembles a credential and carries none.
ORDINARY_TEXTS = [
    "how to set DATABASE_URL in prisma",
    "postgres://localhost:5432/app",
    "postgres://user@host/db",
    "redis://localhost:6379/0",
    # documentation placeholders and development defaults
    "postgresql://user:password@localhost:5432/mydb",
    "postgres://postgres:postgres@localhost:5432/app",
    "amqp://guest:guest@localhost:5672/",
    "postgres://app:${DB_PASSWORD}@db/app",
    "postgres://app:$DB_PASSWORD@db/app",
    "mysql://user:<password>@host/db",
    "mysql://root:{password}@host/db",
    # schemas and templates
    '"api_key": {"type": "string"}',
    '{"password": "string"}',
    '{"password": null}',
    '"api_key": "$OPENAI_API_KEY"',
    "set the api_key and password fields",
    "AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key)",
    "aws_secret_access_key = <your secret access key>",
    "AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}",
    # things that share a prefix
    "the JWT header starts with eyJ",
    _b64({"alg": "HS256", "typ": "JWT"}),
    "a task-proj-management-and-other-long-words-here",
    "risk-admin-dashboard-for-the-whole-company",
    "see https://gitlab.com/glpat/docs",
    "github_pat_ tokens are fine-grained",
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN PGP PUBLIC KEY BLOCK-----",
]

# Files that hold credentials and were read as ordinary ones.
CREDENTIAL_FILES = [
    "token.json",
    "/home/u/.codex/auth.json",
    "/home/u/.docker/config.json",
    "~/.docker/config.json",
    "file:///home/u/.docker/config.json",
    "/home/u/.config/gcloud/application_default_credentials.json",
    "id_ed25519",
    "/backup/keys/id_ecdsa",
    "/backup/keys/id_dsa",
    "/backup/keys/id_ed25519_sk",
    "/proc/self/environ",
    "/proc/4242/environ",
    "file:///proc/self/environ",
    "/home/u/.gnupg/secring.gpg",
    "/home/u/.pgpass",
    "/home/u/.vault-token",
]

# Files whose names only sound like the ones above.
FILES_THAT_ONLY_SOUND_SECRET = [
    "tokens.json",                    # design tokens
    "tokenizer.json",
    "authors.json",
    "src/auth.ts",
    "token.go",
    "config.json",
    "docker/config.json",
    ".docker/nginx/default.conf",     # a project's own .docker directory
    ".docker/php/Dockerfile",
    "src/environ.ts",
    "proc/environ.py",
    "id_card.png",
    "id_ed25519.pub",
]
