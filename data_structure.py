import Crypto	
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import json
from collections import OrderedDict
from digital_signature import *

import requests
import dateutil.parser
import urllib.request

PE_int = int('0x10001',16)
PE_hex = '0x10001'
TXN_FEE = 50
AMOUNT_REWARD = 1000
#input : 
# publickey_from : hex string, hex string 
# publickey_to   : hex string, hex string
# amount         : hex string
# time           : UCT time in ISO 8601 format
# parent         : hex string
#output: ordered dict
VERBOSE_FLAG = False
def verbose_print(*args):
	if VERBOSE_FLAG:
		for arg in args:
			print(arg),
	return
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

def get_rewards(user,roots):
	try:
		roots[user] +=AMOUNT_REWARD
	except:
		roots[user] = AMOUNT_REWARD
	return 
def pay_txn_fee(user,roots):
	roots[user] -=TXN_FEE
	return 
def get_txn_fee(user,roots,count):
	roots[user] += TXN_FEE*count
	return
def pay_txn_amount(user,roots,amount):
	roots[user] -=amount
	return 
def get_txn_amount(user,roots,amount):
	try:
		roots[user]+= amount
	except:
		roots[user] = amount
	return


# input : string (transaction only, not transaction sig)
# output : boolean
def verify_transaction_format(txn_string_obj):
	# 1 type check
	try:
		txn = json.loads(txn_string_obj)
	except:
		verbose_print("txn json loads failed")
		return False
	# 2 entity check
	key_given = txn.keys()
	keys_txn = ['parent','type','amount','to','from','timestamp','nonce']
	if not (('type' in key_given ) and (txn['type'] == 'transaction')):
		verbose_print("txn type check failed")
		return False
	if not (('from' in key_given) and (is_hex_type(txn['from'])) ):
		verbose_print("txn from hex key failed")
		return False
	if not (('to' in key_given) and (is_hex_type(txn['to']))):
		verbose_print("txn to hex key check failed")
		return False
	if not (('amount' in key_given) and (is_hex_type(txn['amount']))):
		verbose_print("txn amount type check failed")
		return False
	if not (('parent' in key_given) and (is_hex_type(txn['parent']))):
		verbose_print("txn parent hex type check failed")
		return False
	if not (('timestamp' in key_given) and (is_time_type(txn['timestamp']))):
		verbose_print("txn timestamp type check failed")
		return False
	if not ('nonce' in key_given and is_str_type(txn['nonce'])):
		verbose_print("nonce not valid")
		return False
	# 3 any other things?
	if (len(key_given)!=len(keys_txn)):
		verbose_print("txn any other type check failed")
		return False
	return True


# input : dictionary (transaction,transaction sig)
# output : boolean
def verify_transaction_signature_format(txn_sig_obj):
	# 1 type check
	txn = txn_sig_obj
	if type(dict())!=type(txn):
		verbose_print("txn sig type dict failed")
		return False
	# 2 entity check
	key_given = txn.keys()
	keys_txn = ['transaction','type','sign']
	if not (('type' in key_given ) and (txn['type'] == 'transaction_sign')):
		verbose_print('signature type check failed')
		return False
	if not (('transaction' in key_given) and (verify_transaction_format(txn['transaction'])) ) :
		verbose_print('verify transaction format failed MAN')
		return False
	if not (('sign' in key_given) and (is_hex_type(txn['sign']))):
		verbose_print('txn signature check failed')
		return False
	# 3 any other things?
	if (len(key_given)!=len(keys_txn)):
		verbose_print('any other things?')
		return False
	return True

# input : string 
# output : boolean
def verify_block_format(block):
	#1 block type check
	try:
		block = json.loads(block)
	except:
		verbose_print("block loads failed")
		return False
	if type(dict())!=type(block):
		verbose_print("type check failed")
		return False

	# 2 block entity check
	key_given_block = block.keys()
	keys_block = ['difficulty','transaction','type','reward','nonce','parent','timestamp']
	if not (('type' in key_given_block ) and (block['type'] == 'block')):
		verbose_print("type check failed")
		return False
	if not (('difficulty' in key_given_block ) and (is_hex_type(block['difficulty'])) ):
		verbose_print("difficulty check failed")
		return False
	if not (('reward' in key_given_block) and (is_hex_type(block['reward']))):
		verbose_print("reward check failed")
		return False
	if  (('transactions' in key_given_block) and (is_list_type(block['transactions']))):
		for txn in block['transactions']:
			if not verify_transaction_signature_format(txn):
				verbose_print("transaction sig format verify failed @@")
				return False
	else:
		verbose_print("transactions type failed")
		return False

	# 3 any other entity?
	if (len(key_given_block)!=len(keys_block)):
		verbose_print("some other entity?")
		return False
	return True
# input : dictionary 
# output : boolean
def verify_block_hash_format(block_hash):
	# 1 type check dict
	if (type(dict())!=type(block_hash)):
		verbose_print("block type error")
		return False
	
	# 2 hash_ entity check
	key_given = block_hash.keys()
	keys = ['hash','block','type']
	if not (('type' in key_given ) and (block_hash['type'] == 'block_hash')):
		verbose_print("type error")
		return False
	if not (('block' in key_given ) and (is_str_type(block_hash['block']))):
		verbose_print("type error")
		return False
	if not (('hash' in key_given) and is_hex_type(block_hash['hash'])):
		verbose_print("type error")
		return False
	# 3 any other entity?
	if (len(key_given)!=len(keys)):
		verbose_print("other entity")
		return False
	# 4 hash value check
	hash_cal = hash_bitcoin(block_hash['block'])
	hash_given = block_hash['hash']
	if (int(hash_cal,16)!=int(hash_given,16)):
		verbose_print("hash value error")
		return False
	
	# 5 block verify
	if (verify_block_format(block_hash['block'])):
		return True
	
	return False

def is_list_type(list_type):
	try:
		if (type([])==type(list_type)):
			return True
		else:
			return False
	except:
		return False
	return False
# input: string
# output bool
def is_time_type(time_str):
	try:
		t = dateutil.parser.parse(time_str)
		return True
	except:
		return False
	return False
#input : stirng
#outpu : bool
def is_str_type(cmp_str):
	try:
		if (type(cmp_str)==type(' ')):
			return True
	except:
		return False
	return False

# input :string
# output : bool
# description: check given string is hex string or not.
def is_hex_type(cmp_str):
	try:
		if (type(int(cmp_str,16))==type(0)):
			return True
	except:
		return False
	return False
def get_p2p_msgs():
	url = "https://gw.kaist.ac.kr/broadcast/get"
	res = requests.get(url)
	data = res.json()
	# for d in data:
	# 	key_list = list(d.keys())
	# 	if ('block' in key_list):
	# 		d['block'] = json.loads(d['block'])
	# 	if ('transaction' in key_list):
	# 		d['transaction'] = json.loads(d['transaction'])
	return data

#input : block_hash_structure
#output : bool
def verify_block(block_struct,roots):
	#format verification
	if not (verify_block_hash_format(block_struct)):
		verbose_print("block verification failed")
		return {'block':"failed"}
	#hash verification
	block = json.loads(block_struct['block'])
	hash_cal = hash_bitcoin(block_struct['block'])
	hash_given = block_struct['hash']
	if (int(hash_cal,16)!=int(hash_given,16)):
		verbose_print("hash verification failed")
		return {'block':"failed"}
	#block verification
	difficulty = int(block['difficulty'],16)
	target = pow(2,512-20-difficulty)
	if not ( (int(block_struct['hash'],16) < target)):
		verbose_print("hash<target operation failed")
		return {'block':"failed"}
	
	#transaction verification
	txns = block['transactions']
	##if somewhere can be wrong... backup needed
	for txn in txns:
		if not verify_transaction_sig(txn,roots):
			verbose_print("transaction verification failed")
			return {'block':"failed"}

	txn_amount = len(txns)
	usr = block['reward']
	get_rewards(usr,roots)
	get_txn_fee(usr,roots,txn_amount)
	return roots

#input : transaction sign
#output : bool
def verify_transaction_sig(transaction,roots):
	#format verification
	if not (verify_transaction_signature_format(transaction)):
		verbose_print("verify_transaction sig format failed!")
		return False
	#signature verification
	txn = transaction
	pk = (json.loads(txn['transaction'])['from'],PE_hex)
	sig_given = txn['sign']
	if verify(pk,txn['transaction'],sig_given):
		verbose_print("verify transaction signature hash failed")
		return False
	## negative balance check ## TODO
	txn_struct = json.loads(txn['transaction'])
	from_key = txn_struct['from']
	to_key = txn_struct['to']
	if not from_key in roots.keys():
		verbose_print('verify transaction invalid user')
		return False
	if roots[from_key] < int(txn_struct['amount'],16)+50: #including transaction fee
		verbose_print("verify transaction negative transaction including fee")
		return False
	verbose_print("valid transaction here!!")
	amount = int(txn_struct['amount'],16)
	get_txn_amount(to_key,roots,amount)
	pay_txn_amount(from_key,roots,amount)
	pay_txn_fee(from_key,roots)
	return True

def post_p2p_msgs(json_dict):
	url = "https://gw.kaist.ac.kr/broadcast/post"
	req = urllib.request.Request(url)
	req.add_header('Content-Type', 'application/json')
	data = urllib.request.urlopen(req,json.dumps(json_dict).encode()).read().decode() #UTF-8 encode
	
	return 


# from data_structure import *
# data = get_p2p_msgs()
# d2 = data[:50]
# make_balance_json(d2)
def print_json_output(orderd_dict):
	print(json.dumps(orderd_dict, ensure_ascii=False, indent="\t"))
	return
#input : list of block hash
#output : longest chain (list of block hash)
def get_longest_chain(data):
	heads = "0000"
	data_rev = data.copy()
	data_rev.reverse()
	
	return

import sys
def main_routine():
	data = get_p2p_msgs()
	longest_chain = get_longest_chain(data)
	make_balance_json(data,sys.argv[2])
	return
# input : block list
# output : file
def make_balance_json(data,hash_end):
	roots = OrderedDict()
	
	valid_block = 0
	invalid_block = 0
	i = 0
	fail_roots = {'block':"failed"}
	for block_hash in data:
		roots_original = roots.copy()
		roots_new = verify_block(block_hash,roots)
		if ( roots_new == fail_roots):
			invalid_block+=1
			roots = roots_original
		else:
			valid_block +=1
			
			verbose_print(i,'th block is invalid')
		i+=1
	print_json_output(roots)
	verbose_print("valid block : ",valid_block)
	verbose_print("invalid block : ",invalid_block)
	return 

if __name__=="__main__":
	# print(sys.argv)

	data = get_p2p_msgs()
	make_balance_json(data,sys.argv[2])
	
