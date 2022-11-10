#! usr/bin/env python3
# additilve cipher 

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



