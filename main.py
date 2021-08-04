from Cryptodome import Random
from ECB import *
from serpent import bitstring2hexstring, hex2string, convertToBitstring
from Cryptodome import Random
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
from hashlib import sha512
from ECDH import curve,scalar_mult
import random
    
def make_a_message_and_signature_to_transmit(keyPair,sharedSecret1,Message):      
    plainText = makptright(Message)
    hexkey = hex(sharedSecret1)
    Ctext = ECBEnc(plainText, hexkey)
    arr = bytes(plainText, 'utf-8')
    hash1 = int.from_bytes(sha512(arr).digest(), byteorder='big')
    signature = pow(hash1, keyPair.d, keyPair.n)  #d  priavet
    print("Signature:", hex(signature))
    print( "\nencryptedMsg(Ctext):", Ctext)
    return  Ctext, signature
    

def on_Message_Ricevere( Ctext, signature,keyPair,res):
    # check if the signature valid is True
    hexkey = hex(res)
    plain = ECBDec(Ctext, hexkey)
    ints = list(plain)
    l = convert(ints)  #convert list to str
    hextlalalaext = bitstring2hexstring(l)
    hex_string = hextlalalaext
    strplaintext = hex2string(hex_string)  # decrypt the message ot calc the hash
    arr = bytes(strplaintext, 'utf-8')
    hash2 = int.from_bytes(sha512(arr).digest(), byteorder='big')
    hashFromSignature = pow(signature, keyPair.e, keyPair.n)    #e -public
    print("Signature valid:", hash2 == hashFromSignature)
   
    print ("The message after dcryption is :\n" ,strplaintext)

def main():
    
    Message = input('Please enter your message:\n')

    print("Basepoint:\t", curve.g)
    #select privet key between 1-n
    aliceSecretKey  = random.randrange(1, curve.n)
    alicePublicKey = scalar_mult(aliceSecretKey, curve.g)


    bobSecretKey  = random.randrange(1, curve.n)
    bobPublicKey = scalar_mult(bobSecretKey, curve.g)


    print("Alice\'s secret key:\t", aliceSecretKey)
    print("Alice\'s public key:\t", alicePublicKey)
    print("Bob\'s secret key:\t", bobSecretKey)
    print("Bob\'s public key:\t", bobPublicKey)

    print("==========================")

    sharedSecret1 = scalar_mult(bobSecretKey, alicePublicKey)
    sharedSecret2 = scalar_mult(aliceSecretKey, bobPublicKey)

    print("==========================")
    print("Bob\'s shared key:\t", sharedSecret1)
    print("Alice\'s shared key:\t", sharedSecret2)

    print("\n==========================")
    print("a(bG): \t", (sharedSecret1[0]))
    print('b(aG)h',(sharedSecret2[0]))

    #Generate 1024-bit RSA key pair (private + public key)
    keyPair = RSA.generate(1024)
    Ctext,signature= make_a_message_and_signature_to_transmit(keyPair,sharedSecret1[0],Message)
    on_Message_Ricevere(Ctext, signature,keyPair,sharedSecret2[0])


main()
