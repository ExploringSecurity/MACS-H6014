# Lab 13 - Digital Signatures

## Lab Overview
This lab attempts to demonstrate the use of OpenSSL to sign and verify an RSA digital signature. We'll then look in detail at what exactly is happening at each step of the process so you'll better understand the process of digitally signing a document.

### RSA sign and verify using OpenSSL

```bash
# Create a test file containing some random data
$ echo 'Lets digitally sign this document' > labfile.txt

# Generate a 2048 bit RSA Private key
$ openssl genrsa -out privatekey.pem 2048

# Separate the public part from the Private key file.
$ openssl rsa -in privatekey.pem -pubout > publickey.pem

# Cat the contents of private key
$ cat privatekey.pem
-----BEGIN RSA PRIVATE KEY-----
...
...
-----END RSA PRIVATE KEY-----
```

### Sign using Openssl
Now that we have created a test file and our Private and Public RSA keys we're going to sign our file.  
We'll be using SHA-256 hashing algorithm and PKCS#1 v1.5 padding scheme.

```bash
# Sign the file using sha1 digest and PKCS1 padding scheme
$ openssl dgst -sha256 -sign privatekey.pem -out labfile.sign labfile.txt

# Dump the signature file
$ hexdump labfile.sign

```

### Verify sign using Openssl
Openssl decrypts the signature to recover our hash and compares it to the hash of the input file.

```bash
# Verify the signature of file
$ openssl dgst -sha1 -verify publickey.pem -signature labfile.sign labfile.txt
Verified OK
```

If everything went well we should have successfully signed and verified our labfile. While the steps look simple enough there are a few extra bits happening behind the scences. So let's look in detail at exactly what is happening during each step.

## RSA signature generation in detail

1. The fisrt step when creating a digital signature is creating a hash of the document or email etc. that we want to sign.
   Our example uses SHA-256 (OpenSSL supports plenty of hash formats.)

```bash
# In MAC OS use shasum (with option -a 256) and use sha256sum in linux
$ shasum -a 256 labfile.txt
```

2. The next step is to pad the hash value, so it is extended to the RSA key size by prefixing padding, this avoids any 'plain RSA' attacks.
   The default padding scheme in openssl is PKCS1, and it works as shown below.
   
> PKCS#1v1.5 padding scheme: 00||01||PS||00||T||H
> PS: Octet string with FF such that length of message is equal to key size.
> T: Identifier of signature scheme (Each scheme has its MAGIC bytes).
> H: Hash value of the message.
> PKCS#1v1.5 padding scheme for SHA-256:

PKCS1 padding scheme for SHA256 digest algorithm
```bash
$ PADDING=0001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
$ ANS1_SHA256_MAGIC=3031300d060960864801650304020105000420
$ SHA256_HASH=`shasum -a 256 myfile.txt | cut -d ' ' -f1`
$ echo $PADDING$ANS1_SHA1_MAGIC$SHA256_HASH

```

3. The next part of the jigsaw is to retrieve the modulus and private exponent from our private key. again we'll use OpenSSL to view the contents of private key:

```bash
$ openssl rsa -in myprivate.pem -text -noout

```

We can then manually tidy up the outputed values.

4. At this stage we have the padded hash, and our RSa values, so we need to sign the hash by encrypting with the extracted RSa values.

```bash
# Sign the message: (padded_hash ** private_exp) % modulus
[python]$ print(hex(pow(padded_hash, private_exp, modulus)))
```

5. Our next step is to verify the signature, this time we'll need to get modulus and public exponent from public key
65537 (0x10001) is widely accepted default public exponent, and the modulus will be the same as used earlier.
   
Our ignature is a binary file which is converted to a big integer and used in authentication.

```bash
$ echo `hexdump labfile.sign | cut -c 9- | tr -cd [:alnum:]`

```

```bash
[python]$ padded_hash = hex(pow(signature, public_exp, modulus))
[python]$ padded_hash
''
```

Our calculated Padded hash in verification should match the padded hash in signing.

6. Our final step is to remove the padding to obtain the hash of message
```bash
[python]$ padded_hash[-40:]
''
```

The Hash obtained above is the SHA256 hash of our lab file.
