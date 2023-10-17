# Lab 6: bit Flipping attack 

Objective: Demonstrate a simple bit Flipping attack ahgainst AES used in CTR mode. 

## Scenario
While we can't break the main AES algorithm (Not yet anyways), we can attack it's integrity. This is because some modes of AES are not good at handling the integrity of the message. The fast stream cipher modes, such as with CTR & GCM are especially prone to this lack of integrity checking, as it is easy to pick off the characters to target.

Let's look at a simple encrypted message, such as : 

```Set student grade to 'F'```

We want to alter the student's grade to a B (we don't want to be too greddy), we can easily do this by flipping a few bits

```Set student grade to 'B'```

In ASCII, a ‘F’ is 01000110, and a ‘B’ is 01000010, and so all I have to do, is to find the place of the character I want to flip in the ciphertext, and then just flip the third least significant bit.

## Worked Example
First, I will encrypt the message using AES CTR mode — a fast stream cipher mode with AES — and use a passphrase of “MACSH6014”. The encryption key will be generated using PBKDF2:

```bash
$ echo "Set student grade to 'F'" | openssl enc -k MACSH6014 -e -aes-128-ctr -pbkdf2 >ciphertext
```

The ciphertext will be in a binary form:

```bash
$ cat ciphertext
Salted__�
         )�D���z�F89�3q����\*>>Y4	�
```

We can then use xxd to convert this binary format into a ciphertext so that we can edit the ciphertext:

```bash
$ xxd ciphertext > data
$ cat data
00000000: 5361 6c74 6564 5f5f 3f4a 1a9b 213b 5086  Salted__?J..!;P.
00000010: a8b0 d396 8bcf f4c7 1cc9 ff2c 78ec 020d  ...........,x...
00000020: f415 48c3 1e17 f70c 6f                   ..H.....o
```

AES CTR is a stream mode, so it is easy to find all of the characters in the cipher, as they map straight to their position in the plaintext. Now, we ignore that last byte (6f) and count back the number of characters to the ciphertext of ‘F’. In this case, it is two characters from the end, so let’s use change the ciphertext to:

```bash
$ nano data
00000000: 5361 6c74 6564 5f5f 3f4a 1a9b 213b 5086  Salted__?J..!;P.
00000010: a8b0 d396 8bcf f4c7 1cc9 ff2c 78ec 020d  ...........,x...
00000020: f415 48c3 1e17 f30c 6f                   ..H.....o
```
In this case, I have changed “f70c” to “f30c”, and only flipped one bit (from  01000110 to 01000010, and which should change a ‘F’ to a ‘B’ ). Now we will convert the cipher back into binary, and decrypt:

```bash
% xxd -r data > ciphertext
% cat ciphertext
Salted__�
         )�D���z�F89�3q����\*>>Y4
% cat ciphertext | openssl enc -k MACSH6014 -d -aes-128-ctr -pbkdf2   
Set student grade to 'B'
```
           
And magically, we have converted our grade from an 'F' to a 'B'

## Why does this happen? 

Well, the integrity checking in OpenSSL is not very good, and it struggles to detect whether bits have been flipped in the cipher.
