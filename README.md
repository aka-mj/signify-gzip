# signify-gzip

This is a simple tool to generate key pairs compatible with OpenBSD's signify tool, and
to sign and verify gzip files using those keys.

## Usage

```
signify-gzip -G [-n] [-c comment] -p pubkey -s seckey
signify-gzip -S [-n] [-passphrase phrase] -s seckey -fin input-file -fout output-file
signify-gzip -V [-q] -p pubkey -fin input-file
```

## Complete Workflow Example

### 1. Generate Key Pair

First, create a public/private key pair. You'll be prompted for a passphrase to protect the secret key:

```bash
signify-gzip -G -p mykey.pub -s mykey.sec
```

With a comment:

```bash
signify-gzip -G -c "Release signing key" -p mykey.pub -s mykey.sec
```

This creates two files:
- `mykey.pub` - Public key (share this with users who need to verify your signatures)
- `mykey.sec` - Secret key (keep this private and secure)

### 2. Sign a gzip File

Create a regular gzip file first, then sign it:

```bash
# Create a gzip file from your data
tar czf mydata.tar.gz /path/to/data

# Sign the gzip file (creates a new signed gzip file)
signify-gzip -S -s mykey.sec -fin mydata.tar.gz -fout mydata.sig.tar.gz
```

You'll be prompted for the passphrase you set when creating the key pair.
The signature is embedded in the gzip file's comment header.

To avoid the passphrase prompt, you can provide it on the command line:

```bash
signify-gzip -S -passphrase "your-passphrase" -s mykey.sec -fin mydata.tar.gz -fout mydata.sig.tar.gz
```

### 3. Verify a Signed gzip File

To verify the signature on a signed gzip file:

```bash
signify-gzip -V -p mykey.pub -fin mydata.sig.tar.gz
```

If the signature is valid, it prints `Verified` and exits with code 0.
If the signature is invalid or the file has been tampered with,
it prints `Failed` and exits with code 1.

After verification, you can extract the gzip file normally:

```bash
# Verify first
signify-gzip -V -p mykey.pub -fin mydata.sig.tar.gz

# If verified, extract the content
tar xzf mydata.sig.tar.gz
```

## Options

- `-G` - Generate a new key pair
- `-S` - Sign a gzip file
- `-V` - Verify a signed gzip file
- `-p <file>` - Public key file
- `-s <file>` - Secret key file
- `-fin <file>` - Input gzip file
- `-fout <file>` - Output gzip file (for signing)
- `-c <comment>` - Comment for the key or signature
- `-n` - Don't prompt for passphrase (read from stdin)
- `-passphrase <phrase>` - Provide passphrase on command line
- `-v` - Show version
- `-h` - Show help


