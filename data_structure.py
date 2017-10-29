import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import json
from collections import OrderedDict
from digital_signature import *

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
	dict_['sign'] = sign(transaction['from'],hash(json.dumps(transaction)))
	
	

	return dict_

#input : 
# transactions : list of orderd dictionary transaction_sign
# reward : hex string
# difficulty : hex string
# nonce : string
# parant : hex string without 0x
#output: ordered dict
def make_block(transactions,reward,difficulty,nonce,parent):
	time = None
	dict_ = OrderedDict()
	dict_['type'] = "block"
	dict_['transaction'] = transactions
	dict_['timestamp'] = time
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
	dict_['hash'] = hash(json.dumps(block))
	return dict_

def verify_transaction():
	return False

def verify_block():
	return False

def make_balance_json():
	return 