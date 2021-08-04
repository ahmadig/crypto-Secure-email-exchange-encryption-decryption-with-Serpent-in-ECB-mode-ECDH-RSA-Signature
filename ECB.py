import random
import string
from serpent import convertToBitstring, stringtohex, makeLongKey, \
    keyLengthInBitsOf, encrypt,decrypt

def makptright(plainText):
    result = plainText
    if len(result) % 16 != 0:
        result += "1"
    while len(result) % 16 != 0:
        result += "0"
    return result


def convert(s):
    new = ""

    for x in s:
        new += str(x)
    return new


def ECBEnc(plainText, key):
    pos = 0
    cipherTextChunks = []
    strigkey = str(key)
    strigkey = strigkey[2:]
    strl = strigkey
    strl = strl.lower()
    bitsInKey = keyLengthInBitsOf(strl)
    rawKey = convertToBitstring(strl, bitsInKey)
    userKey = makeLongKey(rawKey)  # for the increption  256

    plainText = str(plainText)
    while pos + 16 <= len(plainText):
        nextPos = pos + 16
        textt = plainText[pos:nextPos]
        toEnc = stringtohex(textt)
        toEnc = convertToBitstring(toEnc, len(toEnc) * 4)
        enc = encrypt(toEnc, userKey)
        cipherTextChunks.append(enc)
        pos += 16
        
    return cipherTextChunks


def ECBDec(cipherTextChunks, key):
    plainText = []
    strigkey = str(key)
    strigkey = strigkey[2:]
    strl = strigkey
    strl = strl.lower()
    bitsInKey = keyLengthInBitsOf(strl)
    rawKey = convertToBitstring(strl, bitsInKey)
    userKey = makeLongKey(rawKey)  # for the increption
    temp = []
    
    for chunk in cipherTextChunks:
        dec = decrypt(chunk, userKey)
        temp.append(dec)
    
    for l in reversed(temp):
        plainText += l

    
    return plainText
