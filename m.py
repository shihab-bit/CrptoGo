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
