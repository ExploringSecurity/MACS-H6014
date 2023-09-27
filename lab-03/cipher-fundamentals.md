# Lab 3: Cipher Fundamentals 

Objective: The objective of this lab is to introduce some of the fundamental principles involved in cryptography, including the usage of Base-64, hexadecimal, the modulus operator some basic operators (such as AND, OR, X-OR, Rotate Right and Rotate Left), and prime numbers. 
 


## Introduction
1. Determine the Base64 and Hex values for the following strings:  
Hello  
hello  
HELLO

2. Determine the following ASCII strings for these encoded formats:  
bGxveWRz  
6E6170696572  
01000001 01101110 01101011 01101100 01100101 00110001 00110010 00110011 

3. Which of the following numbers are prime?  
91, 421, 1449, 100001, 1433241314213

> :bulb: Apart from 2 and 3, all primes fit into the equation 6k ± 1

4. Discuss the best method to test for prime numbers?

5. What is the GCD of the following:  
105, 35  
88, 46  
123456, 2346 

6. Two numbers are co-prime if they do not share co-factors, apart from 1, which is gcd(a,b)=1.  Determine if the following values are co-prime: 
5435 and 634  
5432 and 634

## Basic Python

7. Using Python, what is the result of 53,431 (mod 453)?  

```python
# In Python, this is:  
print (53431 % 453) 
```
> :bulb: The mod operator results in the remainder of an integer divide. For example, 31 divided by 8 is 3 remainder 7, thus 31 mod 8 equals 7. Often in cryptography the mod operation uses a prime number, such as:  
Result = valuex mod (prime number) 

8. Using Python, what is the results of the following:

```python
print (0x43 | 0x21)  
print (0x43 & 0x21)  
print (0x43 ^ 0x21)  
```

> :writing_hand: Using a pen and paper, prove that these results are correct. 

9. Using Python, what is the hex, octal, character, and binary equivalents of the value of 93:   

```python
x=93 
print ("Dec:\t",x)
print ("Bin:\t",bin(x)) 
print ("Hex:\t",hex(x)) 
print ("Oct:\t",oct(x)) 
print ("Char:\t",chr(x))
```

10. Using Python, what is the Base-64 conversion for the string of “crypto”?  

```python
import base64 
str=b"crypto"
print (base64.b64encode(str))  
```

11. If we use a string of “crypto1”, what do you observe from the Base64 conversion compared to the result in the previous question? 


## What I should have learnt from this lab?
The key things learnt:  
- Some fundamental principles around number and character formats, including binary, hexadecimal and Base64.  
- How to run a Python program and change some of the parameters.
- Some fundamentals around prime numbers and mod operations.
