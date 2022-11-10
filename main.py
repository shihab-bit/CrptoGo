#!/usr/bin/env python3
import subprocess
def main():
    print("#########################################")
    print("welcome to CryptoGo tool for all ciphers")
    print("#########################################")
    print("Enter number of your choec")
    print("1-additilve cipher 2-multiplicative cipher 3-affine cipher 4-autokey cipher\n5-playfair cipher 6-vigenere 7-hell cipher 8-rail fence cipher \n9-aes cipther 10-rsa cipher 11- diffie-hellman")
    print("#########################################")
    print("NOTE :when you input string use ' ' and Caapital")
    i=input()
    if(i=='1'):
         p= subprocess.Popen('python add.py', shell=True)
         out, err=p.communicate()
         main()
    elif(i=='2'):
         p= subprocess.Popen('python m.py', shell=True)
         out, err=p.communicate()
         main()
    elif(i=='3'):
         p= subprocess.Popen('python af.py', shell=True)
         out, err=p.communicate()
         main()
    elif(i=='4'):
         p= subprocess.Popen('python au.py', shell=True)
         out, err=p.communicate()
         main()
    elif(i=='5'):
         p= subprocess.Popen('python pl.py', shell=True)
         out, err=p.communicate()
         main()     
    elif(i=='6'):
         p= subprocess.Popen('python ve.py', shell=True)
         out, err=p.communicate()
         main() 
    elif(i=='7'):
         p= subprocess.Popen('python hill.py', shell=True)
         out, err=p.communicate()
         main()    
    elif(i=='8'):
         p= subprocess.Popen('python ra.py', shell=True)
         out, err=p.communicate()
         main()
    elif(i=='9'):
         p= subprocess.Popen('python aes.py', shell=True)
         out, err=p.communicate()
         main()
    elif(i=='10'):
         p= subprocess.Popen('python res.py', shell=True)
         out, err=p.communicate()
         main()
    elif(i=='11'):
         p= subprocess.Popen('python man.py', shell=True)
         out, err=p.communicate()
         main()
    else:
         print("hi")    
    
     
if __name__ == '__main__':
    main() 
