#import OpenSSL
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
random_generator = Random.new().read

def generateKey(keysize):
	#implement here
	key = RSA.generate(keysize, random_generator)
	pk = (key.e,key.n)
	sk = (key.d,key.n)
	return (pk,sk)
def sign(sk,msg):
	#implement here
	msg = msg.encode()
	m = hashlib.sha512()
	m.update(msg)
	hashed_msg = m.digest()

	#msg to byte convert
	int_msg = int.from_bytes(hashed_msg,byteorder='big')
	sig = pow(int_msg,sk[0],sk[1])

	return sig

def verify(pk,msg,sig):
	#implement here

	#decrypt msg 
	decrypt_msg = pow(sig,pk[0],pk[1])
	decrypt_msg = decrypt_msg.to_bytes((decrypt_msg.bit_length()+7)//8,'big')
	
	#hash msg calculate
	msg = msg.encode()
	m = hashlib.sha512()
	m.update(msg)
	hashed_msg = m.digest()
	print('decrypt_msg : ',decrypt_msg)
	print('msg : ',msg.decode())

	#compare two
	if (hashed_msg==decrypt_msg):
		return True
	else:
		return False



################
#   for test   #
################

def test(msg,msg2):
	print('input msg : ',msg)
	
	pk,sk = generateKey(2048)
	print('sk,pk : ',sk,pk)
	sig = sign(sk,msg)
	print('sig : ',sig)
	v = verify(pk,msg,sig)
	print("sig verification with msg result : ",v)

	print('compare two different case')
	pk2,sk2 = generateKey(2048)
	print('sk2,pk2 :',sk2,pk2)
	sig2 = sign(sk2,msg2)
	print('sig : ',sig2)
	v2 = verify(pk2,msg2,sig2)
	print("sig2 verification with msg2 result : ",v2)
	v3 = verify(pk2,msg,sig2)
	print('sig2 verification with msg result : ',v3)
	v4 = verify(pk2,msg2,sig)
	print('sig verification with msg2 result : ',v3)
	return v






