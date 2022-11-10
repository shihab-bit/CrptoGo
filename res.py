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
