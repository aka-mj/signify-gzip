# signify-gzip

This is a simple tool to generate key pairs compatible with OpenBSD's signify tool, and to sign and verify gzip files using those keys.

## Usage

```
signify-gzip -G [-n] [-c comment] -p pubkey -s seckey
signify-gzip -S [-n] [-passphrase phrase] -s seckey -fin input-file -fout output-file
signify-gzip -V [-q] -p pubkey -fin input-file
```


