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
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBHn6wE3700LuH
HutIK5DBTiStE7KD1JI4rVwbtPWxdWYyk8cAJlQzP5y8eBHYl/6SvKwcZa9mdkWF
Px+TP4nSmzT8cBekiXrYWHHX1NtluM/fA1X3FXbDno9LIuKSvhYSC35knz2NZrQY
etyO+AZjeri+sQQ86qpU3u4Mm1pKD0P/4o0g1Y2iqSAAAkv+rey+MMp2HgtP+C1N
rMEOibGUPWJ9AWl6xye+oDdgavWQ/FSeOj+/VGaYW+nt0SWgzziD4qIno0U9ACi4
YKrlQmUmKGK/8ycuh5e8T8jP8AftZJZsD6TQUnx0FwOcQBy7Df3cZFgj7v3D7JMH
4xSXgRq7AgMBAAECggEAQGerp4ww9HOifus0W3LQCW/GsoQVrnqXs1g5ljHxGJhH
F4oKPYYK4baOzpoalYoHSCetHKFa8Eh0Yf5NyP1RORAzCRdXAzQoaHuCqBDghJmw
lbcWldsuKwo3zr6ZIohLcwQrSGKFFCHS4TEkWnfkJYwZjdsaRziZysk4SbML1xOQ
glOb9DLKaGPG8aODwX3FWG0GT+gX7AjwhPTa10tr9NO0mFru3XWe5N4KOVEt3TrY
K3WUOfmys/7Ur6VddPYDlwNo0fCOn48ChQAYIJohSgp8uvk1oEjPQ5u7us66w23C
IrexPF10vPx1l0u8jU2Hq8jUiVM15uiPU8NjBne7jQKBgQDwIh5bsxtkTzj+0BOJ
pJiJdXtLBEYtnEO+7WKMvJnRbCd1LCKnpYaHwglE+6ORWMbq4UsfzB+tAV3hxpgE
cKx1M5s9dDfgjCN2TcEK4f48xYY6rJTP23qjdi0CoXofl8YvhZ4coT/jCJ2lIXyt
AoQ0HEoOc0es3OcsN5J3hPufFQKBgQDN4SBmBWwTubkwoCoyY+eFxprptaTG5s2o
6XEiVVekUytNwJGORlJfGp23O/MGd0AJphjd7i6b2s2Oc7f3SCQ1eMIZJMJuHMgs
3hGtNHNzA9p35IqmOj5kqKzjGA32OVOKAOwVSW+S8X69C59/YV7y70Ucn5XPAylV
Z5+r3IXGjwKBgBzrrwZSQulI1U9zFfdM2IYtnQTC5gTWPh5/jo/uowPi57mn8CCK
wfIVv3IMcH2v2H0vVxHkTqhSctEfTu2x+ENBTOAQ4C3uEtNLuAUshKcjDvCAGogS
IeoP8InRkti9OcQ9bnZ6QSyBvCLILrDTjcKM6apl3esGy9y6cKxuWrOlAoGAFx1V
g97L+ZL6hckVs76fuddIgUDRlTtIj9RVzWMDigGEdSBPt0eR6/eTCYWDjZBJ8kth
s1kQhpMUTRAU8YB6AD7km+oSokY8+zybg3TGGX2vQ5K3Nl6Hrsl5T63ds21QQchE
uUcbbcYLUrJBYA3QmTnf6ozIRwu10k7mEGeb5WUCgYEAvNBjjx2TIekH7q580LiE
5tlIlmu128KCqCzIsRRijrqO8SlzZkYSab4t1pH6F1ychFctjOPs525Ueknf5Jhw
Axu9lyOAZCmVoXKhrgJBN4AsamM2RWE/zpUiJvh+5jt8RLv2VNr2jYJrocneXuDl
plOcGIs2yaLFgV5+TM/sCEY=
-----END PRIVATE KEY-----
```

### Sign using Openssl
Now that we have created a test file and our Private and Public RSA keys we're going to sign our file.  
We'll be using SHA-256 hashing algorithm and PKCS#1 v1.5 padding scheme.

```bash
# Sign the file using sha1 digest and PKCS1 padding scheme
$ openssl dgst -sha256 -sign privatekey.pem -out labfile.sign labfile.txt

# Dump the signature file
$ hexdump labfile.sign
0000000 96ae f1cb 57fa f290 07b6 0cd8 f132 d926
0000010 0a20 9dd0 a355 db10 6a83 1e95 f5c9 1eb1
0000020 8c8d 3ef8 aa04 743d f271 ae3c 13a5 6608
0000030 7486 a437 b2fb ae03 c4ed 918c c6b2 5439
0000040 130d df11 1437 8a42 ab2c 0f44 4da5 ad95
0000050 cdd0 31cb b03d 7cc6 5d60 1d94 c9ce 051b
0000060 260f 7310 3d1f 3843 aa96 d802 6ae7 5ad8
0000070 627d 6ff4 fed0 c4e3 7ed9 8bfe 9de9 bfe0
0000080 5f2f ac16 2fa9 7a4b 245d 08ba f2d1 04a3
0000090 0bb0 ef48 310a 44af cf1e 2bef 4064 2f32
00000a0 3cad b847 ffaa 977e 0b8c 64dc 8178 617d
00000b0 e089 0366 378a 2315 cc0b f468 6a8b 9f21
00000c0 e48e 60e5 29c2 a244 aa89 d627 eb8a 99b6
00000d0 553c e2c6 85e7 fd13 709f 0dec 240b 4670
00000e0 a0de ce02 0e04 646e b71c 3c70 edf8 ea93
00000f0 99ea 749f 76af 486a 992e 1e3d a21f 5803
0000100
```

### Verify sign using Openssl
Openssl decrypts the signature to recover our hash and compares it to the hash of the input file.

```bash
# Verify the signature of file
$ openssl dgst -sha256 -verify publickey.pem -signature labfile.sign labfile.txt
Verified OK
```

If everything went well we should have successfully signed and verified our labfile. While the steps look simple enough there are a few extra bits happening behind the scences. So let's look in detail at exactly what is happening during each step.

## RSA signature generation in detail

1. The fisrt step when creating a digital signature is creating a hash of the document or email etc. that we want to sign.
   Our example uses SHA-256 (OpenSSL supports plenty of hash formats.)

```bash
# In MAC OS use shasum (with option -a 256) and use sha256sum in linux
$ shasum -a 256 labfile.txt
706c5545219e5ca960a96c6398c8e46945ed0eab678113a9ea4114800376b501 labfile.txt
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
$ PADDING=0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
$ ANS1_SHA256_MAGIC=3031300d060960864801650304020105000420
$ SHA256_HASH=`shasum -a 256 labfile.txt | cut -d ' ' -f1`
$ echo $PADDING$ANS1_SHA1_MAGIC$SHA256_HASH
0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a050004141010a7e761610980ac591359c871f724de150f23440ebb5959ac4c0724c91d91
```

3. The next part of the jigsaw is to retrieve the modulus and private exponent from our private key. again we'll use OpenSSL to view the contents of private key:

```bash
$ openssl rsa -in privatekey.pem -text -noout

Private-Key: (2048 bit, 2 primes)
modulus:
    00:c1:1e:7e:b0:13:7e:f4:d0:bb:87:1e:eb:48:2b:
    90:c1:4e:24:ad:13:b2:83:d4:92:38:ad:5c:1b:b4:
    f5:b1:75:66:32:93:c7:00:26:54:33:3f:9c:bc:78:
    11:d8:97:fe:92:bc:ac:1c:65:af:66:76:45:85:3f:
    1f:93:3f:89:d2:9b:34:fc:70:17:a4:89:7a:d8:58:
    71:d7:d4:db:65:b8:cf:df:03:55:f7:15:76:c3:9e:
    8f:4b:22:e2:92:be:16:12:0b:7e:64:9f:3d:8d:66:
    b4:18:7a:dc:8e:f8:06:63:7a:b8:be:b1:04:3c:ea:
    aa:54:de:ee:0c:9b:5a:4a:0f:43:ff:e2:8d:20:d5:
    8d:a2:a9:20:00:02:4b:fe:ad:ec:be:30:ca:76:1e:
    0b:4f:f8:2d:4d:ac:c1:0e:89:b1:94:3d:62:7d:01:
    69:7a:c7:27:be:a0:37:60:6a:f5:90:fc:54:9e:3a:
    3f:bf:54:66:98:5b:e9:ed:d1:25:a0:cf:38:83:e2:
    a2:27:a3:45:3d:00:28:b8:60:aa:e5:42:65:26:28:
    62:bf:f3:27:2e:87:97:bc:4f:c8:cf:f0:07:ed:64:
    96:6c:0f:a4:d0:52:7c:74:17:03:9c:40:1c:bb:0d:
    fd:dc:64:58:23:ee:fd:c3:ec:93:07:e3:14:97:81:
    1a:bb
publicExponent: 65537 (0x10001)
privateExponent:
    40:67:ab:a7:8c:30:f4:73:a2:7e:eb:34:5b:72:d0:
    09:6f:c6:b2:84:15:ae:7a:97:b3:58:39:96:31:f1:
    18:98:47:17:8a:0a:3d:86:0a:e1:b6:8e:ce:9a:1a:
    95:8a:07:48:27:ad:1c:a1:5a:f0:48:74:61:fe:4d:
    c8:fd:51:39:10:33:09:17:57:03:34:28:68:7b:82:
    a8:10:e0:84:99:b0:95:b7:16:95:db:2e:2b:0a:37:
    ce:be:99:22:88:4b:73:04:2b:48:62:85:14:21:d2:
    e1:31:24:5a:77:e4:25:8c:19:8d:db:1a:47:38:99:
    ca:c9:38:49:b3:0b:d7:13:90:82:53:9b:f4:32:ca:
    68:63:c6:f1:a3:83:c1:7d:c5:58:6d:06:4f:e8:17:
    ec:08:f0:84:f4:da:d7:4b:6b:f4:d3:b4:98:5a:ee:
    dd:75:9e:e4:de:0a:39:51:2d:dd:3a:d8:2b:75:94:
    39:f9:b2:b3:fe:d4:af:a5:5d:74:f6:03:97:03:68:
    d1:f0:8e:9f:8f:02:85:00:18:20:9a:21:4a:0a:7c:
    ba:f9:35:a0:48:cf:43:9b:bb:ba:ce:ba:c3:6d:c2:
    22:b7:b1:3c:5d:74:bc:fc:75:97:4b:bc:8d:4d:87:
    ab:c8:d4:89:53:35:e6:e8:8f:53:c3:63:06:77:bb:
    8d
prime1:
    00:f0:22:1e:5b:b3:1b:64:4f:38:fe:d0:13:89:a4:
    98:89:75:7b:4b:04:46:2d:9c:43:be:ed:62:8c:bc:
    99:d1:6c:27:75:2c:22:a7:a5:86:87:c2:09:44:fb:
    a3:91:58:c6:ea:e1:4b:1f:cc:1f:ad:01:5d:e1:c6:
    98:04:70:ac:75:33:9b:3d:74:37:e0:8c:23:76:4d:
    c1:0a:e1:fe:3c:c5:86:3a:ac:94:cf:db:7a:a3:76:
    2d:02:a1:7a:1f:97:c6:2f:85:9e:1c:a1:3f:e3:08:
    9d:a5:21:7c:ad:02:84:34:1c:4a:0e:73:47:ac:dc:
    e7:2c:37:92:77:84:fb:9f:15
prime2:
    00:cd:e1:20:66:05:6c:13:b9:b9:30:a0:2a:32:63:
    e7:85:c6:9a:e9:b5:a4:c6:e6:cd:a8:e9:71:22:55:
    57:a4:53:2b:4d:c0:91:8e:46:52:5f:1a:9d:b7:3b:
    f3:06:77:40:09:a6:18:dd:ee:2e:9b:da:cd:8e:73:
    b7:f7:48:24:35:78:c2:19:24:c2:6e:1c:c8:2c:de:
    11:ad:34:73:73:03:da:77:e4:8a:a6:3a:3e:64:a8:
    ac:e3:18:0d:f6:39:53:8a:00:ec:15:49:6f:92:f1:
    7e:bd:0b:9f:7f:61:5e:f2:ef:45:1c:9f:95:cf:03:
    29:55:67:9f:ab:dc:85:c6:8f
exponent1:
    1c:eb:af:06:52:42:e9:48:d5:4f:73:15:f7:4c:d8:
    86:2d:9d:04:c2:e6:04:d6:3e:1e:7f:8e:8f:ee:a3:
    03:e2:e7:b9:a7:f0:20:8a:c1:f2:15:bf:72:0c:70:
    7d:af:d8:7d:2f:57:11:e4:4e:a8:52:72:d1:1f:4e:
    ed:b1:f8:43:41:4c:e0:10:e0:2d:ee:12:d3:4b:b8:
    05:2c:84:a7:23:0e:f0:80:1a:88:12:21:ea:0f:f0:
    89:d1:92:d8:bd:39:c4:3d:6e:76:7a:41:2c:81:bc:
    22:c8:2e:b0:d3:8d:c2:8c:e9:aa:65:dd:eb:06:cb:
    dc:ba:70:ac:6e:5a:b3:a5
exponent2:
    17:1d:55:83:de:cb:f9:92:fa:85:c9:15:b3:be:9f:
    b9:d7:48:81:40:d1:95:3b:48:8f:d4:55:cd:63:03:
    8a:01:84:75:20:4f:b7:47:91:eb:f7:93:09:85:83:
    8d:90:49:f2:4b:61:b3:59:10:86:93:14:4d:10:14:
    f1:80:7a:00:3e:e4:9b:ea:12:a2:46:3c:fb:3c:9b:
    83:74:c6:19:7d:af:43:92:b7:36:5e:87:ae:c9:79:
    4f:ad:dd:b3:6d:50:41:c8:44:b9:47:1b:6d:c6:0b:
    52:b2:41:60:0d:d0:99:39:df:ea:8c:c8:47:0b:b5:
    d2:4e:e6:10:67:9b:e5:65
coefficient:
    00:bc:d0:63:8f:1d:93:21:e9:07:ee:ae:7c:d0:b8:
    84:e6:d9:48:96:6b:b5:db:c2:82:a8:2c:c8:b1:14:
    62:8e:ba:8e:f1:29:73:66:46:12:69:be:2d:d6:91:
    fa:17:5c:9c:84:57:2d:8c:e3:ec:e7:6e:54:7a:49:
    df:e4:98:70:03:1b:bd:97:23:80:64:29:95:a1:72:
    a1:ae:02:41:37:80:2c:6a:63:36:45:61:3f:ce:95:
    22:26:f8:7e:e6:3b:7c:44:bb:f6:54:da:f6:8d:82:
    6b:a1:c9:de:5e:e0:e5:a6:53:9c:18:8b:36:c9:a2:
    c5:81:5e:7e:4c:cf:ec:08:46
```

We can then manually tidy up the outputed values.  
n =0x00c11e7eb0137ef4d0bb871eeb482b90c14e24ad13b283d49238ad5c1bb4f5b175663293c7002654333f9cbc7811d897fe92bcac1c65af667645853f1f933f89d29b34fc7017a4897ad85871d7d4db65b8cfdf0355f71576c39e8f4b22e292be16120b7e649f3d8d66b4187adc8ef806637ab8beb1043ceaaa54deee0c9b5a4a0f43ffe28d20d58da2a92000024bfeadecbe30ca761e0b4ff82d4dacc10e89b1943d627d01697ac727bea037606af590fc549e3a3fbf5466985be9edd125a0cf3883e2a227a3453d0028b860aae54265262862bff3272e8797bc4fc8cff007ed64966c0fa4d0527c7417039c401cbb0dfddc645823eefdc3ec9307e31497811abb  
e = 65537  
d=0x4067aba78c30f473a27eeb345b72d0096fc6b28415ae7a97b358399631f1189847178a0a3d860ae1b68ece9a1a958a074827ad1ca15af0487461fe4dc8fd51391033091757033428687b82a810e08499b095b71695db2e2b0a37cebe9922884b73042b4862851421d2e131245a77e4258c198ddb1a473899cac93849b30bd7139082539bf432ca6863c6f1a383c17dc5586d064fe817ec08f084f4dad74b6bf4d3b4985aeedd759ee4de0a39512ddd3ad82b759439f9b2b3fed4afa55d74f603970368d1f08e9f8f02850018209a214a0a7cbaf935a048cf439bbbbacebac36dc222b7b13c5d74bcfc75974bbc8d4d87abc8d4895335e6e88f53c3630677bb8d  


4. At this stage we have the padded hash, and our RSA values, so we need to sign the hash by encrypting with the extracted RSa values.

```bash
# Sign the message: (padded_hash ** private_exp) % modulus
[python]$ print(hex(pow(padded_hash, private_exp, modulus)))
0xe034c675661445f03394962d50fcef9b2f2baa28ab141d53881a1aa282280f067c4f5b7d55e0a018496630f7a369580f45a3bddf72ad600f1c174bd4914f0f84e099897b757389cfe4dc28b05a1c84a31eceaed9e19f37189d61e5263425a25b3710b863941b31d4b6967c0d05b70bf7f5d3672b75cf16a693ac7213f0341866428201d0ddb4fb1dabfa3dbc3489494dc840b0309cf98e4b35f12789e92408abf82bbb3163796f64b67efc2f708e0a41e32a50ee2f8e93ab7608511d7e5a6cc9dd9bb1bb5def97151f6202b6bca7ab093e7698c28d1e6b758ebb5b793475f44e3adeaa8c900493f153c2341f8b8d204a1b38912c24279dd2295fed6fe2a979
```

5. Our next step is to verify the signature, this time we'll need to get modulus and public exponent from public key
65537 (0x10001) is widely accepted default public exponent, and the modulus will be the same as used earlier.
   
Our signature is a binary file which is converted to a big integer and used in authentication.

```bash
$ hexdump labfile.sign
0000000 96ae f1cb 57fa f290 07b6 0cd8 f132 d926
0000010 0a20 9dd0 a355 db10 6a83 1e95 f5c9 1eb1
0000020 8c8d 3ef8 aa04 743d f271 ae3c 13a5 6608
0000030 7486 a437 b2fb ae03 c4ed 918c c6b2 5439
0000040 130d df11 1437 8a42 ab2c 0f44 4da5 ad95
0000050 cdd0 31cb b03d 7cc6 5d60 1d94 c9ce 051b
0000060 260f 7310 3d1f 3843 aa96 d802 6ae7 5ad8
0000070 627d 6ff4 fed0 c4e3 7ed9 8bfe 9de9 bfe0
0000080 5f2f ac16 2fa9 7a4b 245d 08ba f2d1 04a3
0000090 0bb0 ef48 310a 44af cf1e 2bef 4064 2f32
00000a0 3cad b847 ffaa 977e 0b8c 64dc 8178 617d
00000b0 e089 0366 378a 2315 cc0b f468 6a8b 9f21
00000c0 e48e 60e5 29c2 a244 aa89 d627 eb8a 99b6
00000d0 553c e2c6 85e7 fd13 709f 0dec 240b 4670
00000e0 a0de ce02 0e04 646e b71c 3c70 edf8 ea93
00000f0 99ea 749f 76af 486a 992e 1e3d a21f 5803
```

Tidy up our file to get the hex value

96aef1cb57faf29007b60cd8f132d9260a209dd0a355db106a831e95f5c91eb18c8d3ef8aa04743df271ae3c13a566087486a437b2fbae03c4ed918cc6b25439130ddf1114378a42ab2c0f444da5ad95cdd031cbb03d7cc65d601d94c9ce051b260f73103d1f3843aa96d8026ae75ad8627d6ff4fed0c4e37ed98bfe9de9bfe05f2fac162fa97a4b245d08baf2d104a30bb0ef48310a44afcf1e2bef40642f323cadb847ffaa977e0b8c64dc8178617de0890366378a2315cc0bf4686a8b9f21e48e60e529c2a244aa89d627eb8a99b6553ce2c685e7fd13709f0dec240b4670a0dece020e04646eb71c3c70edf8ea9399ea749f76af486a992e1e3da21f5803

```bash
[python]$ print(hex(pow(signature, public_exp, modulus)))
0x53848143a3ca2b58993595b5ffaf56478b05261578d070db82dcb69372e35d5f5d0cf11845da79d76ff49fb161f1671fde83da15b409473a02760f77f76942148fd4c22aa72ec8a2c8a57293664b0d09a4dd1580c4a7271ff48e2af816f565cfb56bcd906544c0a6d9a305e55a84132641df62bca19cab1b30f9524a53f0d9bfda5fed1442993818380b550e0ede99a8a55521607fdb90ac7575ca8519468bb4e0a914d7ccc91a846edaf3c5b6f6a54def3c2d703fe6449cda3075beacb484443e0ed42d22e6f649fda2093240911088291909bbffeb9aab966d0ebe6a69c5e327c0938f630886f0c660e73d754e90788821fe96509e45306314ec3ecbcea90c
```

Our calculated Padded hash in verification should match the padded hash in signing.

6. Our final step is to remove the padding to obtain the hash of message
```bash
[python]$ padded_hash[-40:]
''
```

The Hash obtained above is the SHA256 hash of our lab file.
