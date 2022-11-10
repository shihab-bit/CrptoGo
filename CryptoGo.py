#!/usr/bin/env python3
import runpy
def main():
    print("welcome to CryptoGo tool for all ciphers")
    print("Enter number of your choec")
    print("1-additilve cipher 2-multiplicative cipher 3-affine cipher 4-autokey cipher\n5-playfair cipher 6-vigenere 7-hell cipher 8-rail fence cipher \n9-aes cipther 10-rsa cipher 11- diffie-hellman")
    i=input()
    if(i=='1'):
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
              mian()
      main()
    elif(i=='2'):
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
            main()
         main()   
    elif(i=='3'):  
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
           main()
        main()
    elif(i=='4'):
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
         main()
       main()
    elif(i=='5'):
       def doplaintext (plainText): 
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
          main()
    main()          
     
if __name__ == '__main__':
    runpy.run_path(path_name='a.py')
    #exec(open(a.py).read())
