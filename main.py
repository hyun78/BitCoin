#import OpenSSL
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import json
from collections import OrderedDict
random_generator = Random.new().read

def routine():
	#1 read key.json, payload.json
	pk,sk = read_key_json('key.json')
	pk2,msg,sig = read_payload_json('payload.json')
	#2 create a file (named signatrue), write result of sign(sk,message)
	signature_file = open('signature','w')
	signature_file.write(sign(sk,msg))
	#3 create a file (named verify), write result of verify(pk,message,sig)
	verify_file = open('verify','w')
	verify_file.write(str(verify(pk,msg,sig)))

	return

#input : string (* not byte)
#output : hash string without 0x
def hash(string_):
	msg = string_.encode()
	m = hashlib.sha512()
	m.update(msg)
	hashed_msg = hex(int.from_bytes(m.digest(),byteorder='big'))[2:]
	return hashed_msg
#input : int
#output : (hex,hex) , (hex,hex)
#             pk    ,     sk
def generateKey(keysize):
	#implement here
	key = RSA.generate(keysize, random_generator)
	pk = (hex(key.e),hex(key.n))
	sk = (hex(key.d),hex(key.n))

	return (pk,sk)

#input  : (hex,hex),str
#output : hex
def sign(sk,msg):
	#implement here
	msg = msg.encode()
	m = hashlib.sha512()
	m.update(msg)
	hashed_msg = m.digest()

	#msg to byte convert
	int_msg = int.from_bytes(hashed_msg,byteorder='big')
	d,N = int(sk[0],16),int(sk[1],16)
	sig = pow(int_msg,d,N)

	return hex(sig)
#input  : (hex,hex),str,hex
#output : Bool
def verify(pk,msg,sig):
	#implement here
	e,N = int(pk[0],16),int(pk[1],16)
	int_sig = int(sig,16)
	#decrypt msg 
	decrypt_msg = pow(int_sig,e,N)
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

#input  : str,hex,hex,hex
#output ??
def make_payload_json(msg,modulus,e,sig,filename):
	

	dict_inside  = OrderedDict()
	dict_outside = OrderedDict()
	dict_inside['modulus'] = modulus
	dict_inside['publicExponent'] = e
	dict_inside['signature'] = sig
	dict_outside['message'] = msg
	dict_outside['sig'] = dict_inside
	make_json_file(filename,dict_outside)

	return

def make_key_json(sk,pk,filename):
	e = pk[0]
	d = sk[0]
	if (pk[1]==sk[1]):
		n = sk[1]
	else:
		return False
	dict_ = OrderedDict()
	dict_['publicExponent'] = e
	dict_['privateExponent'] = d
	dict_['modulus'] = n
	make_json_file(filename,dict_)

	return

def make_json_file(filename,orderd_dict):
	with open(filename, 'w', encoding="utf-8") as make_file:
		json.dump(orderd_dict, make_file, ensure_ascii=False, indent="\t")
	return


def read_json_file(filename):
	data = None
	with open(filename, encoding="utf-8") as data_file:    
		data = json.load(data_file, object_pairs_hook=OrderedDict)
	return data

def read_key_json(filename):
	data = read_json_file(filename)
	e = data['publicExponent']
	d = data['privateExponent']
	N = data['modulus']
	pk = e,N
	sk = d,N
	return pk,sk
def read_payload_json(filename):
	data = read_json_file(filename)
	msg = data['message']
	sig = data['sig']['signature']
	e = data['sig']['publicExponent']
	N = data['sig']['modulus']
	pk = e,N
	
	return pk,msg,sig
def mk_sign(transaction):
	
	sign_structure = {
		"type": "transaction_sign",
		"transaction" : JSON.stringify(transaction),
		"sign" : sign(transaction['from'],hash(JSON.stringfy(transaction)))
	};

	return sign_structure

def make_block(transactions,reward,difficulty,nonce,parent):
	time = None
	block = {
		"type":"block",
		"transactions":[transactions],
		"timestamp":time,
		"nonce" : nonce,
		"parent" : parent };
	
	return block
def make_block_hash(block):
	blcok_hash = {
	"type" : "block_hash",
	"block": JSON.stringify(block),
	"hash" : hash(JSON.stringify(block))
	};
	return block_hash
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
	print('sig verification with msg2 result : ',v4)

	###### IO TEST
	
	filename1 = 'key.json'
	filename2 = 'payload.json'
	msg = 'PMS'

	pk,sk = generateKey(2048)
	sig = sign(sk,msg)

	make_key_json(sk,pk,filename1)
	make_payload_json(msg,sk[1],pk[0],sig,filename2)
	print('sig verification with msg',verify(pk,msg,sig))

	
	pk_read,sk_read = read_key_json(filename1)
	pk_read2,msg_read,sig_read = read_payload_json(filename2)
	#test 1 pk and sk is same?
	print("test pk,sk in key and pk,sk ",pk==pk_read,sk==sk_read)
	#test 2 input sig verification 
	print("test sig in payload with pk_read ",verify(pk_read2,msg_read,sig_read),verify(pk_read,msg_read,sig_read))
	#test 3 sig and sig_read compare
	print("test sig in file and sig ",sig == sig_read)

	sig_read_made = sign(sk_read,msg_read)
	print(sig_read_made==sig)
	print('sig verification with msg',verify(pk,msg,sig))
	return v






