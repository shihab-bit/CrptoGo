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
