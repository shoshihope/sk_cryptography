# =========================================================================================
# Code to encrypt and decrypt RSA
# =========================================================================================

# =========================================================================================
# Notes on RSA
# =========================================================================================

# Concept:
# Choose two large primes p and q, p != q
# Compute their product, n = pq. 
# Factoring n is considered a classically intractable problem
# Compute the euler totient function phi(n) = (p-1)(q-1)
# This computes the number of relatively prime numbers there are to n
# Choose a public exponent such that gcd(e, phi(n)) == 1
# The private exponent, d, is the modular inverse of e modulo phi(n)
# d == e^{-1} % phi(n) => ed == 1 % phi(n)
# public key: n, e
# private key: d, p, q

# =========================================================================================
# Import packages
# =========================================================================================

from sage.all import *

from helper_functions import *

# =========================================================================================
# Functions
# =========================================================================================

# Function to ecrypt RSA
def rsa_encrypt(m, e, n):
    """
    Function to encrypt a message using RSA

    Args:
    m (Integer or int): message the user wishes to encrypt
    n (Integer or int): modulus for RSA scheme (product of two large primes)
    e (Integer or int): public exponent for RSA scheme

    Output:
    output (Integer): encrypted message
    """
    if not isinstance(m, (int, Integer)) or not isinstance(e, (int, Integer)) or not isinstance(n, (int, Integer)):
        return 'Invalid input'
    m, e, n = Integer(m), Integer(e), Integer(n)
    if m < 0 or m >= n:
        return 'Invalid input'
    return power_mod(m, e, n)

# Function to decrypt RSA
def rsa_decrypt(c, d, n):
    """
    Function to decrypt RSA given you know the private exponent

    Args:
    c (Integer or int): ciphertext to be decrypted
    d (Integer or int): private exponent
    n (Integer or int): modulus (product of two large primes)

    Output:
    Plaintext message as a Integer
    """
    if not isinstance(c, (int, Integer)) or not isinstance(d, (int, Integer)) or not isinstance(n, (int, Integer)):
        return 'Invalid input'
    c, d, n = Integer(c), Integer(d), Integer(n)
    if c < 0 or c >= n:
        return 'Invalid input'
    return power_mod(c, d, n)

# Function to calculate the private exponent, d
def rsa_private_exponent_phi(e, p, q):
    """
    Computes the private exponent for RSA given the user chooses two large primes and the public exponent

    Args:
    e (Integer or int): public exponent, need gcd(e, phi(n)) == 1 to be true
    p (Integer or int): a large prime number
    q (Integer or int): a large prime number not equal to p

    Output: 
    d (Integer) the private exponent, n (Integer) public modulo
    """
    if not all(isinstance(x, (int, Integer)) for x in (e, p, q)):
        return 'Invalid input'
    e, p, q = Integer(e), Integer(p), Integer(q)
    if p == q:
        raise ValueError("p and q must be distinct primes.")
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi(n).")
    d = inverse_mod(e, phi)  
    n = p * q
    return d, n

