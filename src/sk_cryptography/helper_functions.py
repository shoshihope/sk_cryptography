# =========================================================================================
# File containing helper functions needed for the rest of the cryptography code in the library
# =========================================================================================

# Must be using a SageMath Python Interpreter
from sage.all import *

def str2num(s): 
    #takes as input a string of characters, capitalizes it and returns the integer (type == Integer, not int)
    #obtained by concatenating the corresponding  ASCII codes
    if type(s) != str:
        return "Invalid input"

    return ZZ(''.join([str(ord(i)) for i in s.upper()]))

def num2str(m): #the inverse of the function in (a), takes as input an integer and returns the corresponding message (capitalized)
    if type(m) != Integer and type(m) != int:
        return "Invalid input"
    m=str(m)
    return ''.join(chr(int(m[i:i+2])) for i in range(0,len(m),2))
    
# Function to remove punctuation
def remove_punctuation(s):
    """
    Takes a string, removes the punctuation and capitalizes the letters
    
    Args:
    s (str)
    
    Output:
    t (str)
    """
    if not isinstance(s, str):
        return 'Invalid input'
    t = ''.join(c for c in s.upper() if 65 <= ord(c) <= 90)
    return t if t else 'Invalid input'

# Function to write a letter mod 26
def str26(s):
    """
    Takes a string and turns each letter into a number mod 26. A -> 0, B -> 1, ..., Z -> 25
    
    Arg:
    s (str)
    
    Output:
    answer (list): contains the numbers mod 26 in the same order they were in the string
    """
    if not isinstance(s,str):
        return 'Invalid input'
    s = remove_punctuation(s)
    if s == 'Invalid input':
        return s
    answer = []
    for i in s:
        answer.append(ord(i)-65)
    return answer

# Function to break text into n-grams
def ngram(s,N):
    """
    Breaks a string up into n-grams
    
    Args:
    s (str): string you want to break up
    N (Integer) or (int): size of the blocks of text you want
    
    Output:
    output (str): the original str s broken up into n-grams
    """
    if (type(s) == str) & ((type(N) == Integer) or type(N) == int):
        if (N > 0):
            s = remove_punctuation(s)
            if s != 'Invalid input':
                output = ""
                for i in range(len(s)):
                    if i == 0:
                        output += s[i]
                    elif (i % N) == 0:
                        output += " "
                        output += s[i]
                    else:
                        output += s[i]
            else:
                output = 'Invalid input'
        else:
            output = 'Invalid input'
    else:
        output = 'Invalid input'
    return output

if __name__ == "__main__":
    print(type(str2num("A cat!")) == Integer)