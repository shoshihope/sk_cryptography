# =========================================================================================
# Code to encrypt and decrypt a Caesar Shift and Vigenere
# =========================================================================================

# =========================================================================================
# Imports
# =========================================================================================
# Must be using a SageMath Python Interpreter
from sage.all import *

# Functions from helper_functions will be needed
from helper_functions import *

# =========================================================================================
# Caesar Shift
# =========================================================================================

# Function to encrypt Caesar shift
def encrypt_caesar_gram(s,k,N):
    """
    This function will take a string and encrypt it using a Caesar shift of the user's choosing.

    Args:
    s (str): string to be encrypted
    k (str): the key, should be a single letter
    N (Integer): output will be N-grams

    Output:
    output (str): an N-gram containing the encrypted s
    """
    # ensure there are no type errors
    if (type(s) == str) & (type(k) == str) & (type(N) == Integer):
        # N must be >0 for ngram to work
        if N > 0:
            s = remove_punctuation(s)
            if s != 'Invalid input':
                # find the ASCII number of the key in modulo 26
                k = ord(k) - 65
                shift = []
                # perform the Caesar shift numerically
                for i in range(len(s)):
                    x = (ord(s[i])-65) + k
                    shift.append(x%26)
                # convert the numbers back to letters
                for j in range(len(shift)):
                    shift[j] = chr(shift[j]+65)
                output = ""
                for k in shift:
                    output += k
            else:
                return('Invalid input')
        else:
            return('Invalid input')
    else:
        return('Invalid input')
    return ngram(output, N)


# Function to decrypt a Caesar shift
def decrypt_caesar(s,k):
    """
    Function to decrypt a Caesar shift, given you know the key

    Args:
    s (str): the string you want to decipher
    k (str): a single character, the key to the cipher

    Output:
    output(str): the decrypted message
    """
    # check user input correct types
    if (type(s) == str) & (type(k) == str):
        if (len(k) == 1):
            s = remove_punctuation(s)
            if s != 'Invalid input':
                k = ord(k)-65
                k = k % 26
                decrypt = []
                for i in s:
                    x = (ord(i) - 65) - k
                    decrypt.append(x % 26)
                for j in range(len(decrypt)):
                    decrypt[j] = chr(decrypt[j]+65)
                output = ""
                for k in decrypt:
                    output += k
            else:
                return('Invalid input')
        else:
            return('Invalid input')
    else:
        return('Invalid input')
    return output


# =========================================================================================
# Vigenere
# =========================================================================================

# Function to encrypt using Vigenere
def encrypt_vigenere(s,k,N):
    """
    Code to encrypt a message using the Vigenere cipher

    Args:
    s (str): message to be encrypted
    k (str): key 
    N (Integer): the encrypted message will be broken into N-grams

    Output:
    output(str): encrypted message
    """
    if (type(s) == str) & (type(k) == str) & (type(N) == Integer):
        s = remove_punctuation(s)
        k = remove_punctuation(k)
        if (N > 0) and (s != 'Invalid input') and (k != 'Invalid input'):
            x = len(k)
            numbers = []
            for i in range(len(s)):
                y = (ord(s[i])-65) + (ord(k[i%x])-65)
                numbers.append(y%26)
            output = ""
            for k in range(len(numbers)):
                numbers[k] = chr(numbers[k]+65)
            for j in numbers:
                output += j
            output = ngram(output, N)
        else:
            output = 'Invalid input'
    else:
        output = 'Invalid input'
    return output

# Function to decrypt Vigenere
def decrypt_vigenere(s,k):
    """
    Decrypts a Vigenere cipher given the user knows the key

    Args:
    s (str): encrypted message
    k (str): key to the Vigenere cipher

    Output:
    output (str): decrypted message 
    """
    t = str26(s)
    if t == 'Invalid input': return t
    if len(k) == 0: return 'Invalid input'
    if str26(k) == 'Invalid input': return 'Invalid input'
    key = (str26(k)*len(s))[:len(s)]
    output = ''
    for i in range(len(t)):
        output += chr(((t[i]-key[i])%26)+65)
    return output