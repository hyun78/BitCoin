import Crypto	
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import json
from collections import OrderedDict
from digital_signature import *

import requests

PE_int = int('0x10001',16)
PE_hex = '0x10001'
#input : 
# publickey_from : hex string, hex string 
# publickey_to   : hex string, hex string
# amount         : hex string
# time           : UCT time in ISO 8601 format
# parent         : hex string
#output: ordered dict
def mk_transaction(publickey_from,publickey_to,amount,time,parent):
	
	dict_ = OrderedDict()
	dict_['type'] = "transaction"
	dict_['from'] = publickey_from
	dict_['to'] = pulbickey_to
	dict_['timestamp'] = time
	dict_['amount'] = amount
	dict_['parent'] = parent
	
	

	return dict_
#input : ordered dictionary transaction
#output: ordered dict
def mk_transaction_sign(transaction):
	
	dict_ = OrderedDict()
	dict_['type'] = "transaction_sign"
	dict_['transaction'] = transaction
	dict_['sign'] = sign(transaction['from'],hash_bitcoin(json.dumps(transaction)))
	
	

	return dict_

#input : 
# transactions : list of orderd dictionary transaction_sign
# timestamp : time
# reward : hex string
# difficulty : hex string
# nonce : string incoded by utf-8
# parant : hex string without 0x
#output: ordered dict
def make_block(transactions,timestamp,reward,difficulty,nonce,parent):
	dict_ = OrderedDict()
	dict_['type'] = "block"
	dict_['transaction'] = transactions
	dict_['timestamp'] = timestamp
	dict_['reward'] = reward
	dict_['difficulty'] = difficulty
	dict_['nonce'] = nonce
	dict_['parent'] = parent
	#make_json_file(filename,dict_)
	
	
	return dict_
#input : 
# block : ordered dict
#output: ordered dict
def make_block_hash(block):
	dict_ = OrderedDict()
	dict_['type'] = "block_hash"
	dict_['block'] = json.dumps(block)
	dict_['hash'] = hash_bitcoin(json.dumps(block))
	return dict_

def verify_transaction(transaction):

	return False

#input : ordered dict
#output : boolean
def verify_block(block):
	#hash(block) < target
	difficulty = int(block['difficulty'],16)
	target = pow(2,512-20-difficulty)
	if (int(hash_bitcoin(json.dumps(block)),16) < target):
		return True
	return False

def make_balance_json():
	return 

def get_p2p_msgs():
	url = "https://gw.kaist.ac.kr/broadcast/get"
	res = requests.get(url)
	data = res.json()
	for d in data:
		key_list = list(d.keys())
		if ('block' in key_list):
			d['block'] = json.loads(d['block'])
		if ('transaction' in key_list):
			d['transaction'] = json.loads(d['transaction'])
	return data
def verify_block_2(block_struct):
	difficulty = int(block_struct['block']['difficulty'],16)
	target = pow(2,512-20-difficulty)
	if (int(block['hash'],16) < target):
		return True
	return False
def post_p2p_msgs():
	url = "https://gw.kaist.ac.kr/broadcast/post"

	return 
def auto_all(data):
	for d in data:
		h = d['hash']
		h2 = hash_bitcoin(json.dumps(d['block']))
		if h==h2 :
			print("FIND!!")
	return

def auto_given(data):
	i =0 
	for d in data:
		h = d['hash']
		dif = int(d['block']['difficulty'],16)
		t = pow(2,512-20-dif)
		if (int(h,16) < t):
			print(i)
			i +=1
	return