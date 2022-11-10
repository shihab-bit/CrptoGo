#! usr/bin/env python3
# additilve cipher 
"""
def  crypto(text , s) : 
     out = ""
     for i in range(len(text)) :
         char = text[i]
         if (char == " "):
            out += " "
         elif (char.isupper()):
            out += chr((ord(char) + s-65)%26 +65)
         else :
            out += chr((ord(char) +s-97)%26 +97)
     return out 
         



def  decrypto(text , s) : 
     out = ""
     for i in range(len(text)) :
         char = text[i]
         if (char == " "):
            out += " "
         elif (char.isupper()):
            out += chr((ord(char) - s-65)%26 +65)
         else :
            out += chr((ord(char) -s-97)%26 +97)
     return out 

i=input ("Enter e for encrypt or d for decrypt: ")

if(i=='e'):
   plain = input ("Enter the message to be encrypted: ")
   key = input ("Enter the Key: ")
   key = int (key)
   ciphertxt = crypto(plain, key)
   print ("encryp is: "+ciphertxt)
elif(i=='d'):
   plain = input ("Enter the message to be encrypted: ")
   key = input ("Enter the Key: ")
   key = int (key)   
  
   print ("########    The decryption Process  ############")
   print (decrypto(plain, key))
else:
   print("e or d just")


"""

#multiplicative cipher 

"""
def Encryption (text,k):
    cipher=""
    for i in range(len(text)):
        char=text[i]
        if (char==" "):
            cipher=cipher+char
        elif (char.isupper()):
            cipher+= chr((ord(char) * k-65)%26 +65)
        else:
            cipher+= chr((ord(char) * k-97)%26 +97)
    return (cipher)
    
    


           
def Decryption(Cipher,k):
    Cipher = Cipher
    for i in range(26):
        if (k*i)%26==1:
            key= i
    plain =''
    for char in Cipher:
         if char==" ":
            plain=plain+char 
         elif char.isupper():
            plain=plain + chr((ord(char) * key -65)%26 +65)
         else:
            plain=plain + chr((ord(char) * key -97)%26 +97)
    return (plain)
      


   

# hack multiplicative cipher 
"""
def Decryption(Cipher):
    Cipher = Cipher
    for i in range(26):
        key= i

        plain =''
        for char in Cipher:
            if char==" ":
                plain=plain+char 
            elif char.isupper():
                plain=plain + chr((ord(char) * key -65)%26 +65)
            else:
                plain=plain + chr((ord(char) * key -97)%26 +97)
        print ("key %s # %s" %  (key,plain))  
"""

i=input ("Enter e for encrypt or d for decrypt: ")

if(i=='e'):
   plain = input ("Enter the message to be encrypted: ")
   key = input ("Enter the Key: ")
   key = int (key)
   ciphertxt = Encryption(plain, key)
   print ("encryp is: "+ciphertxt)
elif(i=='d'):
   plain = input ("Enter the message to be encrypted: ")
   key = input ("Enter the Key: ")
   key = int (key)   
   print ("########    The decryption Process  ############")
   print (Decryption(plain, key))
else:
   print("e or d just")

"""
#  affine cipher 


def Encryption (text,k1,k2):
    plain=text
    key1=k1
    key2=k2
    cipher=''
    for char in plain:
        if char==" ":
            cipher=cipher+char
        elif char.isupper():
            cipher=cipher + chr((ord(char) * key1 + key2 -65)%26 + 65)
        else:
            cipher=cipher + chr((ord(char) * key1 + key2 -97)%26 + 97)
    return (cipher)

def Decryption(Cipher,k1,k2):
    Cipher = Cipher
    for i in range(26):
        if (k1*i)%26==1:
            key1= i
    plain =""
    for char in Cipher:
         if char==" ":
            plain+=char 
         elif char.isupper():
            s=ord(char)
            plain+= chr(( (s - k2) * key1 -65)%26 +65)
         else:
            s=ord(char)
            plain+= chr(( (s - k2 ) * key1 -97)%26 +97)
    return (plain)
    
i=input ("Enter e for encrypt or d for decrypt: ")

if(i=='e'):
   plain = input ("Enter the message to be encrypted: ")
   key1 = input ("Enter the Key2: ")
   key1 = int (key1)
   key2 = input ("Enter the Key1: ")
   key2 = int (key2)
   ciphertxt = Encryption(plain, key1,key2)
   print ("encryp is: "+ciphertxt)
elif(i=='d'):
   plain = input ("Enter the message to be encrypted: ")
   key1 = input ("Enter the Key2: ")
   key1 = int (key1)
   key2 = input ("Enter the Key1: ")
   key2 = int (key2)
   print ("########    The decryption Process  ############")
   print (Decryption(plain, key1,key2))
else:
   print("e or d just")    


 #autokey cipher
"""
alphabet = "abcdefghijklmnopqrstuvwxyz"
index = dict(zip(alphabet,range(len(alphabet))))
letter = dict(zip(range(len(alphabet)),alphabet))
def crypt(message,key):
    Cipher = ""
    Cipher =Cipher +letter[((index[message[0]]+ index[key[0]]) %26)]
    for i in range(1,len(message)): 
        
           Cipher =Cipher +letter[((index[message[i]]+ index[message[i-1]]) %26)]
            
    return Cipher
        
 
def decrypt(message,key):
    plain = ""
    plain =plain +  letter[((index[message[0]]- index[key[0]]) %26)]
    for i in range(1,len(message)):
           plain += letter[((index[message[i]]- index[plain[i-1]]) %26)]
    return plain
             
    
i=input ("Enter e for encrypt or d for decrypt: ")

if(i=='e'):
   plain = input ("Enter the message to be encrypted: ")
   key = input ("Enter the Key: ")
   key = key
   ciphertxt = crypt(plain, key)
   print ("encryp is: "+ciphertxt)
elif(i=='d'):
   plain = input ("Enter the message to be encrypted: ")
   key = input ("Enter the Key: ")
   key =  key   
  
   print ("########    The decryption Process  ############")
   print (decrypt(plain, key))
else:
   print("e or d just")  
"""
 

# playfair cipher  

"""

def doplaintext (plainText): 


     # append X if Two letters are being repeated 


     for s in range(0,len(plainText)+1,2): 


          if s<len(plainText)-1: 


               if plainText[s]==plainText[s+1]: 


                    plainText=plainText[:s+1]+'x'+plainText[s+1:] 


     # append X if the total letters are odd, to make  plaintext even 


     if len(plainText)%2 != 0: 


          plainText = plainText[:]+'x' 


     return plainText 
 
def key_gen (): 


     key_5x5 = [['l','g','d','b','a'], 


                    ['q','m','h','e','c'], 


                   ['u','r','n','i','f'], 


                    ['x','v','s','o','k'], 


                   ['z','y','w','t','p']] 


     return key_5x5 

def encrypt(text): 


     message = doplaintext(text) 


     k = key_gen() 


     message.replace("j","i") 


     cipher='' 


     for m in range(0, len(message)-  1, 2): 


          for i in range(5): 


               for j in range(5): 


                    if message[m] == k[i][j]: 


                         i1=i 


                         j1=j 


                    if message[m+1] == k[i][j]: 


                         i2=i 


                         j2=j
          if i1==i2: 


               if j1 != 4: 


                    cipher=cipher+k[i1][j1+1] 


               else: 


                    cipher=cipher+k[i1][0] 





               if j2!=4: 


                    cipher=cipher+k[i2][j2+1] 


               else: 


                    cipher=cipher+k[i2][0]
          if j1==j2: 


               if i1 != 4: 


                    cipher=cipher+k[i1+1][j1] 


               else: 


                    cipher=cipher+k[0][j1] 





               if i2!=4: 


                    cipher=cipher+k[i2+1][j2] 


               else: 


                    cipher=cipher+k[0][j2] 


          if i1 != i2 and j1 != j2: 


               cipher=cipher+k[i1][j2] 


               cipher=cipher+k[i2][j1] 


     return cipher                     
     

def decrypt(text): 


      message = text 


      k = key_gen() 





      plain='' 


      for m in range(0, len(message)-  1, 2): 





          for i in range(5): 


               for j in range(5): 


                    if message[m] == k[i][j]: 


                         i1=i 


                         j1=j 


                    if message[m+1] == k[i][j]: 


                         i2=i 


                         j2=j
          if i1==i2: 


                    if j1 != 0: 


                         plain=plain+k[i1][j1-1] 


                    else: 


                         plain=plain+k[i1][4] 




                    if j2!=0: 


                         plain=plain+k[i2][j2-1] 


                    else: 


                         plain=plain+k[i2][4]    
          if j1==j2: 


                  if i1 != 0: 


                       plain=plain+k[i1-1][j1] 


                  else: 


                       plain=plain+k[4][j1] 





                  if i2!=0: 


                       plain=plain+k[i2-1][j2] 


                  else: 


                       plain=plain+k[4][j2] 


          if i1 != i2 and j1 != j2: 


                  plain=plain+k[i1][j2] 


                  plain=plain+k[i2][j1] 


      return plain      
      
      

i=input ("Enter e for encrypt or d for decrypt: ")

if(i=='e'):
   plain = input ("Enter the message to be encrypted: ")
   ciphertxt = encrypt(plain)
   print ("encryp is: "+ciphertxt)
elif(i=='d'):
   plain = input ("Enter the message to be encrypted: ")
   print ("########    The decryption Process  ############")
   print (decrypt(plain))
else:
   print("e or d just")
"""
#  vigenere 
"""
from random import sample
from itertools import product as col


def generator(key,char,length):
    char_len = key.count(char)   
    key_piece = key[:length - char_len:]
    list_keys = [key_piece+"".join(i) for i in list(col([chr(i) for i in range(65, 65+26)], repeat=char_len))]
    return list_keys
	
def vigenere(x,key):
    lst_final = []
    code = list(x)
    j = 0
	
    for i,char in enumerate(code):
        if char.isalpha():
            code[i] = key[(i+j)%len(key)]
            if encrypt:
                lst_final.append((ord(x[i]) + ord(code[i]) - 65 * 2) % 26)
            else:
                lst_final.append((ord(x[i]) - ord(code[i])) % 26)
        else:
            lst_final.append(ord(char))
            j -=1

    for i,char in enumerate(code):
        if char.isalpha():
            lst_final[i] = chr(lst_final[i] + 65)
        else:
            lst_final[i] = chr(lst_final[i])
			
    return ''.join(lst_final)

print("Welcome to Vigenere cipher")

if input('Encrypt or Decrypt : ').lower() == 'encrypt':
    x = input('Enter the text : ').upper()
    key = input('Enter the key : ').upper()
    encrypt = True
    print(vigenere(x,key))
else:
    x = input('text : ').upper()
    encrypt = False
    if input('have you the key (y/n) : ') == "y":
        key = input('Enter the key : ').upper()
        print(vigenere(x,key))
    else:
        abc = list("ABCDEFGHIJKHIJKLMNOPQRSTUVWXYZ")
        question = input('Enter a part of the key or length (answer by 1 or 2 or nothing): ')
        if question == '1':
            key = input('*use \'?\' for the missing letter in the key (C?? or CL? refer for ex to CLE): ').upper()
            list_of_keys = generator(key,'?',len(key))
            for k in list_of_keys:
                print(f'for {k} ==> {vigenere(x,k)}')
			
        elif question == '2':
            length = int(input('Enter the length: '))
            while True:
                key_gen = ''.join(sample(abc,length))
                print(f"for {key_gen} = {vigenere(x,key_gen)}")
                if input('continue(y/n) ... : ')== "n":
                    break
        else:
            print("S0rry this script cannot find your encrypted text")
"""
#hell cipher 

"""
import numpy as np


def encrypt(msg):
    # Replace spaces with nothing
    msg = msg.replace(" ", "")
    # Ask for keyword and get encryption matrix
    C = make_key()
    # Append zero if the messsage isn't divisble by 2
    len_check = len(msg) % 2 == 0
    if not len_check:
        msg += "0"
    # Populate message matrix
    P = create_matrix_of_integers_from_string(msg)
    # Calculate length of the message
    msg_len = int(len(msg) / 2)
    # Calculate P * C
    encrypted_msg = ""
    for i in range(msg_len):
        # Dot product
        row_0 = P[0][i] * C[0][0] + P[1][i] * C[0][1]
        # Modulate and add 65 to get back to the A-Z range in ascii
        integer = int(row_0 % 26 + 65)
        # Change back to chr type and add to text
        encrypted_msg += chr(integer)
        # Repeat for the second column
        row_1 = P[0][i] * C[1][0] + P[1][i] * C[1][1]
        integer = int(row_1 % 26 + 65)
        encrypted_msg += chr(integer)
    return encrypted_msg

def decrypt(encrypted_msg):
    # Ask for keyword and get encryption matrix
    C = make_key()
    # Inverse matrix
    determinant = C[0][0] * C[1][1] - C[0][1] * C[1][0]
    determinant = determinant % 26
    multiplicative_inverse = find_multiplicative_inverse(determinant)
    C_inverse = C
    # Swap a <-> d
    C_inverse[0][0], C_inverse[1][1] = C_inverse[1, 1], C_inverse[0, 0]
    # Replace
    C[0][1] *= -1
    C[1][0] *= -1
    for row in range(2):
        for column in range(2):
            C_inverse[row][column] *= multiplicative_inverse
            C_inverse[row][column] = C_inverse[row][column] % 26

    P = create_matrix_of_integers_from_string(encrypted_msg)
    msg_len = int(len(encrypted_msg) / 2)
    decrypted_msg = ""
    for i in range(msg_len):
        # Dot product
        column_0 = P[0][i] * C_inverse[0][0] + P[1][i] * C_inverse[0][1]
        # Modulate and add 65 to get back to the A-Z range in ascii
        integer = int(column_0 % 26 + 65)
        # Change back to chr type and add to text
        decrypted_msg += chr(integer)
        # Repeat for the second column
        column_1 = P[0][i] * C_inverse[1][0] + P[1][i] * C_inverse[1][1]
        integer = int(column_1 % 26 + 65)
        decrypted_msg += chr(integer)
    if decrypted_msg[-1] == "0":
        decrypted_msg = decrypted_msg[:-1]
    return decrypted_msg

def find_multiplicative_inverse(determinant):
    multiplicative_inverse = -1
    for i in range(26):
        inverse = determinant * i
        if inverse % 26 == 1:
            multiplicative_inverse = i
            break
    return multiplicative_inverse


def make_key():
     # Make sure cipher determinant is relatively prime to 26 and only a/A - z/Z are given
    determinant = 0
    C = None
    while True:
        cipher = input("Input 4 letter cipher: ")
        C = create_matrix_of_integers_from_string(cipher)
        determinant = C[0][0] * C[1][1] - C[0][1] * C[1][0]
        determinant = determinant % 26
        inverse_element = find_multiplicative_inverse(determinant)
        if inverse_element == -1:
            print("Determinant is not relatively prime to 26, uninvertible key")
        elif np.amax(C) > 26 and np.amin(C) < 0:
            print("Only a-z characters are accepted")
            print(np.amax(C), np.amin(C))
        else:
            break
           #print(make_key())
    return C

def create_matrix_of_integers_from_string(string):
    # Map string to a list of integers a/A <-> 0, b/B <-> 1 ... z/Z <-> 25
    integers = [chr_to_int(c) for c in string]
    length = len(integers)
    M = np.zeros((2, int(length / 2)), dtype=np.int32)
    iterator = 0
    for column in range(int(length / 2)):
        for row in range(2):
            M[row][column] = integers[iterator]
            iterator += 1
    return M

def chr_to_int(char):
    # Uppercase the char to get into range 65-90 in ascii table
    char = char.upper()
    # Cast chr to int and subtract 65 to get 0-25
    integer = ord(char) - 65
    return integer

if __name__ == "__main__":
    msg = input("Message: ")
    encrypted_msg = encrypt(msg)
    print(encrypted_msg)
    decrypted_msg = decrypt(encrypted_msg)
    print(decrypted_msg)
 
"""
#rail fence cipher 
"""

def encryptRailFence(text, key):

	rail = [['\n' for i in range(len(text))]
				for j in range(key)]
	
	dir_down = False
	row, col = 0, 0
	
	for i in range(len(text)):
		
		if (row == 0) or (row == key - 1):
			dir_down = not dir_down
		
		rail[row][col] = text[i]
		col += 1
		
		if dir_down:
			row += 1
		else:
			row -= 1
	result = []
	for i in range(key):
		for j in range(len(text)):
			if rail[i][j] != '\n':
				result.append(rail[i][j])
	return("" . join(result))
	
def decryptRailFence(cipher, key):

	rail = [['\n' for i in range(len(cipher))]
				for j in range(key)]
	
	dir_down = None
	row, col = 0, 0
	
	for i in range(len(cipher)):
		if row == 0:
			dir_down = True
		if row == key - 1:
			dir_down = False
		
		rail[row][col] = '*'
		col += 1
		
		if dir_down:
			row += 1
		else:
			row -= 1
			
	index = 0
	for i in range(key):
		for j in range(len(cipher)):
			if ((rail[i][j] == '*') and
			(index < len(cipher))):
				rail[i][j] = cipher[index]
				index += 1
		
	result = []
	row, col = 0, 0
	for i in range(len(cipher)):
		
		if row == 0:
			dir_down = True
		if row == key-1:
			dir_down = False

		if (rail[row][col] != '*'):
			result.append(rail[row][col])
			col += 1
			
		if dir_down:
			row += 1
		else:
			row -= 1
	return("".join(result))

i=input ("Enter e for encrypt or d for decrypt: ")

if(i=='e'):
   plain = input ("Enter the message to be encrypted: ")
   key = input ("Enter the Key: ")
   key = int (key)
   ciphertxt = encryptRailFence(plain, key)
   print ("encryp is: "+ciphertxt)
elif(i=='d'):
   plain = input ("Enter the message to be encrypted: ")
   key = input ("Enter the Key: ")
   key = int (key)   
  
   print ("########    The decryption Process  ############")
   print (decryptRailFence(plain, key))
else:
   print("e or d just")
	

"""
#aes
"""


#
# This is a simple script to encrypt a message using AES
# with CBC mode in Python 3.
# Before running it, you must install pycryptodome:
#
# $ python -m pip install PyCryptodome
#
# Author.: José Lopes
# Date...: 2019-06-14
# License: MIT
##


from hashlib import md5
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


if __name__ == '__main__':
    i=input ("Enter e for encrypt or d for decrypt: ")

    if(i=='e'):
       print('TESTING ENCRYPTION')
       msg = input('Message...: ')
       pwd = input('Password..: ')
       print('Ciphertext:', AESCipher(pwd).encrypt(msg).decode('utf-8'))
    elif(i=='d'):
       print('\nTESTING DECRYPTION')
       cte = input('Ciphertext: ')
       pwd = input('Password..: ')
       print('Message...:', AESCipher(pwd).decrypt(cte).decode('utf-8'))
    else:
       print("e or d just")
    

"""
# rsa cipher

"""
p = input ("Enter the p: ")
p= int (p)
q = input ("Enter the q: ")
q= int (q)
n = p * q
phi = (p - 1) * (q - 1)

def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return -1
    
def generate_e_keypair(p, q,n,phi):

    for i in range(phi):
        if(1<i<phi and gcd(i, phi)==1 and gcd(i,n)==1):
           e = i
           print(e)
           break
    return e
    
def generate_d_keypair(p, q,phi):
    for i in range(phi):
        if((i*e)%phi==1):
           d = i
           print(d)
    return d
          
e=generate_e_keypair(p, q,n,phi)
d=generate_d_keypair(p, q,phi) 

def encrypt(msg, e,n):
    en=(msg ** e)
    c= en % n
    return c

    #unpack key value pair
    e, n = package
    msg_ciphertext = [pow(ord(c), e, n) for c in msg_plaintext]
    return msg_ciphertext
 
def decrypt(msg,d,n):
    en = (msg ** d)
    p= en % n
    return p

    d, n = package
    msg_plaintext = [chr(pow(c, d, n)) for c in msg_ciphertext]
    # No need to use ord() since c is now a number
    # After decryption, we cast it back to character
    # to be joined in a string for the final result
    return (''.join(msg_plaintext))
 
           
#print(generate_keypair(p, q))
#print(q,p,n,phi,e,d)

i=input ("Enter e for encrypt or d for decrypt: ")

if(i=='e'):
   plain = input ("Enter the message int to be encrypted: ")
   plain = int(plain)
   
   ciphertxt = encrypt(plain,e,n)
   print ("encryp is: ")
   print(ciphertxt)
elif(i=='d'):
   plain = input ("Enter the message to be encrypted: ")
   plain = int(plain)
   print ("########    The decryption Process  ############")
   print (decrypt(plain,d,n))
else:
   print("e or d just")
"""
#hill-man
"""
from random import randint

if __name__ == '__main__':

	# Both the persons will be agreed upon the
	# public keys G and P
	# A prime number P is taken
	
	P= input ("Enter tThe Value of P is : ")
	P=int(P)
	# A primitive root for P, G is taken
	G= input ("Enter tThe Value of G is : ")
	G=int(G)
	
	
	print('The Value of P is :%d'%(P))
	print('The Value of G is :%d'%(G))
	
	# Alice will choose the private key a
	a= input ("Enter The Private Key a for Alice is  : ")
	a=int(a)
	
	print('The Private Key a for Alice is :%d'%(a))
	
	# gets the generated key
	x = int(pow(G,a,P))
	
	# Bob will choose the private key b
	b= input ("Enter The Private Key b for Bob is  : ")
	b=int(b)
	
	print('The Private Key b for Bob is :%d'%(b))
	
	# gets the generated key
	y = int(pow(G,b,P))
	
	
	# Secret key for Alice
	ka = int(pow(y,a,P))
	
	# Secret key for Bob
	kb = int(pow(x,b,P))
	
	print('Secret key for the Alice is : %d'%(ka))
	print('Secret Key for the Bob is : %d'%(kb))
"""
