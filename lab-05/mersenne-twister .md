# Lab 5: Breaking Mersenne Twister 

Objective: We want to show how easy it is to break a non-cryptograpgic PRNG. 

When auditing a code base from a security standpoint, a common mistake is the usage of a PRNG instead of a cryptographically secure pseudorandom number (CSPRNG). This may be due to a lack of knowledge of the developer or because PRNGs are usually more efficient than CSPRNGs. The usage of a PRNG instead of a CSRPNG is easy to detect given access to the source code, but the associated risk is well-understood only in the cryptographic community. Therefore, we want to show how easy it is to break a PRNG, in this case an instance of MT19937 – by far the most widely used PRNG, given just 624 consecutive outputs.


## Scenario
A possible attack scenario is as follows. Assume a web server uses MT19937 for generating session tokens. An attacker can query the server for a sequence of 624 outputs by repeatedly logging in and out and recording the session tokens. From these outputs the attacker may be able to clone the PRNG and generate the next outputs and consequently the next session tokens. As a result, the attacker is able to hijack all future sessions as long as its cloned PRNG is manually synchronized with the PRNG on the server.


## Background
Our analysis focuses on the Mersenne Twister. This is the most widely used pseudorandom number generator (PRNG). We focus on the version MT19937. It is used by default in many libraries and programs such as PHP, Python, Ruby, Microsoft Excel, and many more.

Note that even though Python uses MT19937 internally, we reimplement it in pure Python. The implementation that is actually used in Python is done within a C module (see https://github.com/python/cpython/blob/3.8/Modules/_randommodule.c ). While our attack works on Pythons random.random(), the presentation of the attack is more straightforward when attacking a reimplementation of MT19937 in pure Python.

The Mersenne Twister MT19937 has an internal state consisting of 624 32-bit integers which is periodically updated. Additionally, the Mersenne Twister contains some static parameters.

```python
class mersenne_rng(object):
    def __init__(self, seed=5489):
        self.state = [0]*624
        self.f = 1812433253
        self.m = 397
        self.u = 11
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
        self.index = 624
        self.lower_mask = (1 << 31)-1
        self.upper_mask = 1 << 31
  ```

## Run the code.

> :bulb: You may need to install z3

Sample code to break [Mersenne Twister]()
```
pip install z3-solver
```

## REFERENCES
- The implementation of MT19937 that we used: (https://github.com/james727/MTP)
- Cloning MT19937 is one of the [cryptopals challenges](https://cryptopals.com/sets/3/challenges/23) . Consequently there are other solutions to this problem out on the Internet such as [thisone](https://blog.infosectcbr.com.au/2019/08/cryptopals-challenge-23-clone-mt19937.html) .
- The original PRNG in Python is available [here](https://github.com/python/cpython/blob/3.8/Modules/_randommodule.c) . We did not use that one directly, because it is a C-module inside of Python and thus is not easy to access directly.
- 
