# =========================================================================================
# Elliptic Curve Cryptography Code
# =========================================================================================

# =========================================================================================
# Import packages
# =========================================================================================

from sage.all import *

from helper_functions import *

from diffie_hellman import ephemeralkey

# =========================================================================================
# Notes on Elliptic Curve Diffie Hellman (ECDH)
# =========================================================================================
# ECDH works the same way as traditional Diffie Hellman but relies on the difficulty of 
# the elliptic curve discrete log problem 
# 
# Public parameter:
# A prime number p used to define the finite field Fp
# An elliptic curve E over Fp defined by some equation of the form y^2 = x^3 + ax + b (mod p)
# A base point G in E(Fp) with order n
# n must be a large prime
# 
# Key generation:
# Alice chooses a prive key, a, from the set {1, 2, ..., n-1}
# Alice computes her public key: A = aG
# Bob chooses a private key, b, from the set {1, 2, ..., n-1}
# Bob computes her public key B = bG
#
# Computing the shared secret:
# Alice computes S = aB = a(bG)
# Bob computes S = bA = b(aG)
# note that ab = ba since we're working over a field
#
# Deriving the key:
# The shared secret is S = (x,y)
#
# Security:
# It is considered classically infeasible to compute a given A and G

# =========================================================================================
# Elliptic Curve Diffie Hellman Code
# =========================================================================================

def pubkey(p,A,B,P,k):
    """
    Function to calculate the public key for ECDH
    Elliptic curve equation: y^2 = x^3 + Ax + B (mod p)

    Args:
    p (int or Integer): large prime p used for modulo
    A (int or Integer): coefficient of x
    B (int or Integer): constant coefficient
    P (tuple): contains the base point G
    k (int or Integer): private key

    Output:
    tuple containing the public key, a point on the elliptic curve
    """
    if (p.is_prime() == False) or p <= 2:
        return "Invalid input"
    try:
        E = EllipticCurve(GF(p), [A,B])
    except:
        return "Invalid input"
    E = EllipticCurve(GF(p), [A,B])
    try:
        P = E(P[0], P[1])
    except:
        return "Invalid input"
    P = E(P[0], P[1])
    kP = k*P
    if kP == E(0):
        return "Invalid input"
    return(kP[0], kP[1])


def ecdh(p, A, B, b, Q):
    """
    Function that computes the shared key (a tuple)

    Args:
    p (int or Integer): large prime p used for modulo
    A (int or Integer): coefficient of x
    B (int or Integer): constant coefficient
    b (int or Integer): Bob's secret key
    Q (tuple): point on the elliptic curve containing Alice's secret key
    """
    E = EllipticCurve(GF(p), [A,B])
    X = E(Q[0], Q[1])
    shared_key = X*b
    return (ZZ(shared_key[0]), ZZ(shared_key[1]))

# =========================================================================================
# Notes on Elliptic Curve Digital Signature Algorithm (ECDSA)
# =========================================================================================
# ECDSA is the elliptic curve analogue of the Digital Signature Algorithm (DSA)
# It’s used to sign messages (to prove authenticity and integrity) and for verification (to check that a signature is valid).
# Security is based on the difficulty of the Elliptic Curve Discrete Logarithm Problem
# 
# Setup:
# A prime p used to define the finite field Fp
# An elliptic field E over Fp
# A base point G on E, G has order n
# n must be a large prime
# Private key: d, a random integer from the set {1, 2, ..., n-1}
# Public key: Q = dG 
# 
# Signing a message:
# Suppose Alice is sending a message to Bob and she wants to sign it
# Alice and Bob will agree on a hash scheme ahead of time (SHA-256 for example)
# First, she will hash the message, e = H(m)
# Alice will select a random nonce k from the set {1, 2, ..., n-1} unique to that signature
# Alice computes the point (x1, y1) = kG
# Next she calculates r = x1 mod n (if r = 0, start over)
# Last compute s = k^{-1} (e + dr) (mod n) (if s = 0, start over)
# Her signature is the pair (r, s)
#
# Verifying a signature:
# Suppose Bob receives a message, m, from Alice with the signature (r,s)
# First, check that r and s are in the set {1, 2, ..., n-1}
# Hash the message e = H(m)
# Compute the inverse w = s^{-1} (mod n)
# Compute u1 = ew (mod n), u2 = rw (mod n)
# Compute the elliptic curve point (x2, y2) = u1G + u2Q
# The signature is valid if r is congruent to x2 mod n
#
# Security:
# Given G and Q, it's classically intractable to compute dd
# (as long as the nonce isn't reusable or predictable)

# =========================================================================================
# Elliptic Curve Digital Signature Algorithm (ECDSA) Code
# =========================================================================================

def ecsigset(q,A,B):
    """
    Function that helps find a secure subgroup for signatures
    Elliptic curve: y^2 = x^3 + Ax + b

    Args:
    q (int or Integer): a large prime
    A (int or Integer): coefficient of x
    B (int or Integer): constant coefficient

    Output:
    The tuple (p, (x,y))
    p (Integer): largest prime factor of the group with cardinality |E|
    (x, y) (tuple of Integers): point G, coordinates on Elliptic curve E(Fq) with order p
    """
    E = EllipticCurve(GF(q), [A,B])
    F = E.cardinality()
    pf = prime_factors(F)
    p = ZZ(pf[len(pf)-1])
    while True:
        G = E.random_element()
        if (G.order()%p) == 0:
            break
    a = ZZ(G.order()/p)
    G = a*G
    return (p,(ZZ(G[0]),ZZ(G[1])))


def ecsig(p,q,A,B,G,d,m):
    """
    Function that returns the EC signature
    Elliptic curve: y^2 = x^3 + Ax + b

    Args: 
    p (int or Integer): a large prime
    q (int or Integer): a large prime
    A (int or Integer): coefficient of x
    B (int or Integer): constant coefficient
    G (tuple): generator point on the elliptic curve E(Fq), has order p
    d (int or Integer): private key
    m (int or Integer): integer representing the message. m must be smaller than p and q

    Output:
    Tuple ((r, s), (x', y')) where (r, s) is a tuple containing the signature and (x', y') is a tuple containing the coordinates of Q = dG
    """
    E = EllipticCurve(GF(q), [A,B])
    G = E(G[0], G[1])
    if G.additive_order() != p:
        return "Invalid input"
    Q = d*G
    if (m >= p) or (m >= q):
        return "Invalid input"
    k = ephemeralkey(p)
    R = IntegerModRing(q)
    r = mod(G[0],p)
    s = power_mod(k,-1,p)
    s = s*(m+r*d)
    s = mod(s,p)
    return ((ZZ(r),ZZ(s)),(ZZ(Q[0]),ZZ(Q[1])))

def ecdsaverify(q,A,B,G,p,Q,m,signature):
    """
    Function to verify EC signature
    Elliptic curve: y^2 = x^3 + Ax + b

    Args:
    p (int or Integer): a large prime
    q (int or Integer): a large prime
    A (int or Integer): coefficient of x
    B (int or Integer): constant coefficient
    Q (tuple): (x', y') the coordinates of the public key
    m (int or Integer): integer representing the message. m must be smaller than p and q
    signature (tuple): (r, s) the signature to verify

    Output:
    Returns a Boolean depending on if the signature can be verified or not
    """
    E = EllipticCurve(GF(q), [A,B])
    G = E(G)
    Q = E(Q)
    if G.additive_order() != p:
        return "Invalid input"
    R = IntegerModRing(p)
    r = R(signature[0])
    s = R(signature[1])
    si= s^(-1)
    ss = ZZ(si)
    C = (ss*m)*G+(ss*ZZ(r))*Q
    if ZZ(C[0])%p == r:
        return True
    else:
        return False