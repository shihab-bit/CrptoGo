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
