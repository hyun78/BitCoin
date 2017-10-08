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
	m = hashlib.sha512()
	m.update(msg)
	hashed_msg = m.digest()

	#msg to byte convert
	int_msg = int.from_bytes(hashed_msg,byteorder='big')
	sig = pow(int_msg,sk[0],sk[1])

	return sig

def verify(pk,msg,sig):
	#implement here
	decrypt_msg = pow(sig,pk[0],pk[1])
	decrypt_msg = decrypt_msg.to_bytes((decrypt_msg.bit_length()+7)//8,'big')
	m = hashlib.sha512()
	m.update(msg)
	hashed_msg = m.digest()
	print('decrypt_msg : ',decrypt_msg)

	if (hashed_msg==decrypt_msg):
		return True
	else:
		return False
"""
test code below
msg = b'hahah end'
sk,pk = generateKey()
sig = sign(sk,msg)
v = verify(pk,msg,sig)

"""

def test(msg):
	print('input msg : ',msg)
	msg = msg.encode()
	sk,pk = generateKey(2048)
	print('sk,pk : ',sk,pk)
	sig = sign(sk,msg)
	print('sig : ',sig)
	v = verify(pk,msg,sig)
	print("result : ",v)
	return v






