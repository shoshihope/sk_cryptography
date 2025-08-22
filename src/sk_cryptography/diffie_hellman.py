# =========================================================================================
# Diffie Hellman and ElGamal Code
# =========================================================================================

# =========================================================================================
# Notes on Diffie Hellman
# =========================================================================================
#
# Diffie Hellman is a key exchange protocol. It allows Alice and Bob to securely exchange 
# a private key over an insecure channel.
#
# Setup:
# A large prime number, p (public)
# A number, g, that is a primitive root modulo p (public)
# Alice chooses a private key, a
# Bob chooses a private key, b
#
# Exchange:
# Alice computes A = g^a % p and transmits it to Bob
# Bob computes B = g^b %p and transmits it to Alice
# 
# Computing the shared secret, s:
# Alice computes s = B^a % p = (g^b)^a % p
# Bob computes s = A^b % p = (g^a)^b % p
# This way Alice and Bob have the same number s, the symmetric key
# 
# Security:
# Eve will know p, g, A, and B
# To compute s, she will need to calculate g^(ab)
# However, to recover a and b, she needs to solve the discrete log problem A = g^b % p or B = g^a % p
# This is considered a classically intractable problem (for large p) 

# =========================================================================================
# Import packages
# =========================================================================================

from sage.all import *

from helper_functions import *

# =========================================================================================
# Diffie Hellman Functions
# =========================================================================================

# Function to compute the public key
def pubkey(p, g, x):
    """
    Function to compute the public key given p, g, and private key x

    Args:
    p (int or Integer): large, odd prime number (public)
    g (int or Integer): a primitive root mod p
    x (int or Integer): Alice or Bob's private key

    Output:
    outputs the public key g^x % p as an Integer
    """
    if not isinstance(g, (int, Integer)) or not isinstance(p, (int, Integer)) or not isinstance(x, (int, Integer)):
        return "Invalid input"
    return(power_mod(g, x, p))

# Function to compute the private and public key
def keygen(p, g):
    """
    Function to randomly generate a private key and compute the public key

    Args:
    p (int or Integer): public modulus
    g (int or Integer): public primitive root mod p

    Output:
    a tuple (privatekey (Integer), publickey (Integer)) that contains 
    a randomly generated private key between p^1/4 and p^3/4 and the public key
    """
    if not isinstance(p, (int, Integer)) or not isinstance(g, (int, Integer)):
        return("Invalid input")
    privatekey = randint(ceil(p^(1/4)),floor(p^(3/4)))
    publickey = pubkey(p, g, privatekey)
    return(ZZ(privatekey), ZZ(publickey))

# Function to compute the shared secret, s
def DH(p, A, y):
    """
    Function to compute s

    Args:
    p (int or Integer): public large prime
    A (int or Integer): Alice's public key
    y (int or Integer): Bob's private key

    Output:
    Private key s as an Integer
    """
    if not isinstance(p, (int, Integer)) or not isinstance(A, (int, Integer)) or not isinstance(y, (int, Integer)):
        return("Invalid input")
    return(ZZ(pow(A, y, p)))

# =========================================================================================
# Notes on ElGamal
# =========================================================================================
#
# ElGamal uses the same math behind Diffie Hellman to create an encryption scheme
# 
# Setup:
# Choose a large prime p (public)
# Choose a primitive root of modulo p, call it g (public)
# Pick a private key, x, such that 1 <= x <= p-2
# Compute the public key, y = g^x % p
# 
# Encryption:
# Suppose Alice wants to send a message, m, to Bob
# Alice converts m to an integer 0 < m < p
# Choose a random ephemeral key, k (changes with each encryption)
# Compute c1 = g^k % p and c2 = m*y^k % p
# The ciphertext is the tuple (c1, c2)
# 
# Decryption:
# Bob uses his private key, x, to recover m
# First compute the shared secret, s
# s = c1^x % p
# Next compute the inverse mod p, s_inv = s^{-1} % p
# Recover the message: m = (c2 * s_inv) % p
#
# ElGamal also relies on the difficulty of computing the discrete log

# =========================================================================================
# ElGamal Functions
# =========================================================================================

def ephemeralkey(p):
    """
    Computes the ephemeral key, k, needed for ElGamal

    Args:
    p (int or Integer): large prime used for modulus

    Output:
    the ephemeral key as an Integer
    """
    if not isinstance(p, (int, Integer)):
        return "Invalid input"
    return ZZ(randint(floor(p^(1/4)), ceil(p^(3/4))))

def elgamalencrypt(p,a,A,s):
    """
    Function to encrypt a message using ElGamal

    Args:
    p (int or Integer): large prime used for modulus
    a (int or Integer): primitive root of modulo p
    A (int or Integer): public key
    s (str): the plaintext, need str2num(s) < p

    Output:
    a tuple containing the ciphertext (c1, c2)
    """
    if not isinstance(p, (int, Integer)) or not isinstance(a, (int, Integer)) or not isinstance(A, (int, Integer)) or not isinstance(s, str):
        return "Invalid input"
    m = str2num(s)
    if m > p:
        return "m is too big to encrypt"
    k = ephemeralkey(p)
    c1 = power_mod(a, k ,p)
    c2 = (m*power_mod(A, k ,p))%p
    return (c1, c2)

def elgamaldecrypt(p,n,c):
    """
    Function to decrypt ElGamal given you know the private key and ciphertext (c1,c2)

    Args:
    p (int or Integer): large prime used for modulus
    n (int or Integer): the private key
    c (tuple of two ints (or Integers)): (c1, c2) the ciphertext

    Output:
    returns a string with the plaintext
    """
    if not isinstance(p (int, Integer)) or not isinstance(n, (int, Integer)) or not isinstance(c, tuple):
        return "Invalid input"
    plaintext = power_mod(c[0], -n, p)
    plaintext = (plaintext * c[1]) % p
    return num2str(plaintext)