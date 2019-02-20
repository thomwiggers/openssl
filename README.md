# OpenSSL with CSIDH

## Usage:
1. Grab [the constant-time CSIDH implementation by Campos, Meyer, Reith + modifications](https://github.com/thomwiggers/constant-csidh-c-implementation)
2. Compile it
3. Put ``libcsidh.a`` into ``csidh/lib``
4. Compile OpenSSL

## Generating a keypair

```
./apps/openssl genpkey -algorithm csidh512 -out csidh.key
./apps/openssl pkey -in csidh.key -pubout -out csidh.pub
```
