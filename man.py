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
