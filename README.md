# env-encrypt-cli

Encrypt and decrypt `.env` file values for secure storage in git.

Values are encrypted with AES-256-GCM while keys remain readable:

```
DB_HOST=enc:v1:base64data...
DB_PORT=enc:v1:base64data...
```

## Install

```bash
npm install -g env-encrypt-cli
```

## Usage

### Encrypt

```bash
# Encrypt .env → .env.encrypted
env-encrypt-cli encrypt -k my-secret-key

# Custom input/output
env-encrypt-cli encrypt -i .env.production -o .env.production.encrypted -k my-secret-key

# Key from environment variable
export ENV_ENCRYPT_KEY="my-secret-key"
env-encrypt-cli encrypt

# Key from file
env-encrypt-cli encrypt --key-file ./secret.key
```

### Decrypt

```bash
# Decrypt .env.encrypted → .env
env-encrypt-cli decrypt -k my-secret-key

# Custom input/output
env-encrypt-cli decrypt -i .env.production.encrypted -o .env.production -k my-secret-key
```

### Rotate Key

```bash
# Re-encrypt all values with a new key
env-encrypt-cli rotate -k old-key --new-key new-key
```

## Key Resolution

Keys are resolved in this order:

1. `--key-file <file>` — read key from a file
2. `-k/--key <value>` — if the value matches `^[A-Z_][A-Z0-9_]*$`, it is treated as an environment variable name; otherwise used as a literal key
3. `ENV_ENCRYPT_KEY` environment variable

## Encrypted Format

Each encrypted value uses the format:

```
enc:v1:<base64(salt + iv + authTag + ciphertext)>
```

- **Algorithm**: AES-256-GCM
- **Key derivation**: scrypt (32-byte salt)
- **IV**: 16 bytes, random per value
- **Auth tag**: 16 bytes (GCM integrity)

## Workflow

1. Add `.env` to `.gitignore`
2. Encrypt: `env-encrypt-cli encrypt -k $KEY`
3. Commit `.env.encrypted`
4. On deploy/checkout: `env-encrypt-cli decrypt -k $KEY`

## License

MIT
