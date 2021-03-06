import Crypto	
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
import json
from collections import OrderedDict
from digital_signature import *

import time
import requests
import dateutil.parser
import urllib.request
import copy
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
		#verbose_print("before : ",user,roots[user])
		roots[user] +=AMOUNT_REWARD
		#verbose_print("after : ",user,roots[user])
	except:
		#verbose_print("before : ",user,0)
		roots[user] = AMOUNT_REWARD
		#verbose_print("after : ",user,roots[user])
	return 
def pay_txn_fee(user,roots):
	#verbose_print("before : ",user,roots[user])
	roots[user] -=TXN_FEE
	#verbose_print("after : ",user,roots[user])
	return 
def get_txn_fee(user,roots,count):
	#verbose_print("before : ",user,roots[user])
	roots[user] += TXN_FEE*count
	#verbose_print("after : ",user,roots[user])
	return
def pay_txn_amount(user,roots,amount):
	#verbose_print("before : ",user,roots[user])
	roots[user] -=amount
	#verbose_print("after : ",user,roots[user])
	return 
def get_txn_amount(user,roots,amount):
	try:
		#verbose_print("before : ",user,roots[user])
		roots[user]+= amount
	except:
		verbose_print("before : ",user,0)
		roots[user] = amount
	#verbose_print("after : ",user,roots[user])
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
def verify_block_format(block_given):
	#1 block type check
	try:
		
		block = json.loads(block_given)
		
	except:
		if type(json.loads(block_given))!=type(dict()):

			verbose_print("block loads failed",block_given,type(block_given),json.loads(block_given),type(json.loads(block_given)),type(dict())==json.loads(block_given))
			return False
		block = json.loads(block_given)
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
	data_total = []
	url = "https://gw.kaist.ac.kr/broadcast/get"
	start_at = 1
	param = {'start_at':start_at}
	res = requests.get(url,params=param)
	data = res.json()
	data_total += data
	while (data!=[]):
		start_at += len(data)
		param = {'start_at':start_at}
		res = requests.get(url,params=param)
		data = res.json()
		data_total += data
			
	# for d in data:
	# 	key_list = list(d.keys())
	# 	if ('block' in key_list):
	# 		d['block'] = json.loads(d['block'])
	# 	if ('transaction' in key_list):
	# 		d['transaction'] = json.loads(d['transaction'])
	return data_total

#input : block_hash_structure
#output : bool
def verify_block(block_struct,roots):
	#format verification
	if not (verify_block_hash_format(block_struct)):
		verbose_print("block verification failed")
		return False
	#hash verification
	block = json.loads(block_struct['block'])
	hash_cal = hash_bitcoin(block_struct['block'])
	hash_given = block_struct['hash']
	if (int(hash_cal,16)!=int(hash_given,16)):
		verbose_print("hash verification failed")
		return False
	#block verification
	difficulty = int(block['difficulty'],16)
	target = pow(2,512-20-difficulty)
	if not ( (int(block_struct['hash'],16) < target)):
		verbose_print("hash<target operation failed")
		return False
	
	
	txns = block['transactions']
	#transaction sort
	roots_new = copy.deepcopy(roots)
	txns = sort_txns(copy.deepcopy(txns))
	txn_amount = len(txns)
	usr = block['reward']
	get_rewards(usr,roots_new)
	
	if txn_amount!=0:
		get_txn_fee(usr,roots_new,txn_amount)
	#transaction verification
	for txn in txns:
		if not verify_transaction_sig(txn,roots_new):
			verbose_print("transaction verification failed",roots_new)
			return False
	return roots_new

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
	amount = int(txn_struct['amount'],16)
	if not from_key in roots.keys():
		verbose_print('verify transaction invalid user',from_key,"\nto :",to_key,"\n amount",amount,"\n roots:",roots)
		return False
	if roots[from_key] < int(txn_struct['amount'],16)+50: #including transaction fee
		verbose_print("verify transaction negative transaction including fee","from : ",from_key,"\nto :",to_key,"\n amount",amount,"\n roots:",roots)
		return False
	verbose_print("valid transaction here!!@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
	
	get_txn_amount(to_key,roots,amount)
	pay_txn_amount(from_key,roots,amount)
	pay_txn_fee(from_key,roots)
	return True
def sort_txns(txn_list):
	sorted_list = []
	txn_list_cpy = copy.deepcopy(txn_list)
	if (txn_list == []):
		return []
	# simple sort
	try:
		iternum = len(txn_list)
		for i in range(iternum):
			idx = 0
			time_now = dateutil.parser.parse(json.loads(txn_list[0]['transaction'])['timestamp'])
			for j in range(len(txn_list)):
				cmp_time = dateutil.parser.parse(json.loads(txn_list[j]['transaction'])['timestamp'])
				if (time_now>cmp_time): # 더 늦은 거래인가?
					idx = j
					time_now = cmp_time
			sorted_list.append(txn_list[idx])
			txn_list.pop(idx)
	except:
		return []
	#print("sort before : \n",txn_list_cpy,"\n sort after \n",sorted_list)
	return sorted_list
def post_p2p_msgs(json_dict):
	url = "https://gw.kaist.ac.kr/broadcast/post"
	req = urllib.request.Request(url)
	req.add_header('Content-Type', 'application/json')
	data = urllib.request.urlopen(req,json.dumps(json_dict).encode()).read().decode() #UTF-8 encode
	print("successfuly posted")
	return 


# from data_structure import *
# data = get_p2p_msgs()
# d2 = data[:50]
# make_balance_json(d2)
def print_json_output(orderd_dict):
	print(json.dumps(orderd_dict, ensure_ascii=False, indent="\t"))
	return

class Block_chain():
	def __init__(self,head_block_hash):
		self.head = Block_node(head_block_hash,{},0,None)		
		self.roots = {}
		self.chains = []
		self.chains.append([self.head]) #first chain added
		return
	def add(self,block_hash):
		#find corresponding parent
		#head노드중 차일드를 찾아서.. 가 아니라.. 체인중에 가능한 친구가 있는지 보자.
		chain_idx = 0
		block_idx = 0
		find_flag = False
		target = None
		try:
			parent_hash = int(json.loads(block_hash['block'])['parent'],16)
		except:
			return False

		for i in range(len(self.chains)):
			for j in range(len(self.chains[i])):
				block = self.chains[i][j]
				#부모 찾기
				if block.is_parent(parent_hash):
					new_roots = copy.deepcopy(block.roots)
					child_node = Block_node(block_hash,new_roots,block.depth,block)
					if not (child_node.format_validity):
						continue
					chain_idx = i
					block_idx = j
					find_flag = True
					target = child_node
					break
			if find_flag==True:
				break
		if find_flag and target.format_validity:
			#마지막에 붙는 것인가? 
			if j == len(self.chains[i])-1:
				self.chains[i].append(target)
			else: #브랜치가 생기는가?
				branch = self.chains[i][:(j+1)]
				branch.append(target)
				self.chains.append(branch)
		else:
			return False
		return True
	def get_longest(self):

		l_list = [len(chain) for chain in self.chains]
		max_l = max(l_list)
		idx = l_list.index(max_l)
		res =self.chains[idx][:]

		return res
	def get_target_hash(self,target_hash):
		chain = self.get_longest()
		idx = 0
		find_flag = False
		for i in range(len(chain)):
			block = chain[i]
			if block.hash==int(target_hash,16):
				find_flag = True
				idx = i
				break;
		if find_flag:
			return chain[:idx][:]
		else:
			return chain[:]
		
class Block_node():
	def __init__(self,block_hash,roots,depth,parent_ptr):
		
		try:
			self.block_hash = block_hash.copy()
			self.roots = copy.deepcopy(roots)
			self.depth = depth+1
			self.parent_ptr = parent_ptr

			roots_new = verify_block(self.block_hash,self.roots)
			if (roots_new):
				self.hash = int(block_hash['hash'],16)
				self.parent = int(json.loads(block_hash['block'])['parent'],16)
				self.format_validity = True
				self.roots = roots_new
				self.dif = int(json.loads(self.block_hash['block'])['difficulty'],16)
				if not (self.verify_difficulty()):
					raise ValueError('verify_block failed')
			else:
				try:
					self.hash = int(block_hash['hash'],16)
				except:
					self.hash = 0
				self.parent = ""
				self.format_validity = False
		except:
			self.format_validity = False
		return
	
	def is_parent(self,parent_hash):
		#is self the parent of child?
		if (parent_hash	 == self.hash) :
			return True
		return False
	def get_depth(self):
		return self.depth
	def verify_difficulty(self):
		if self.depth<= 10 :
			if self.dif!=0: #initial dif
				return False
			return True
		else:
			n = self.depth%10
			ten_before = self.go_up_n(10)
			dif_before = ten_before.dif #10n + 1th block
			if n==0:
				n = 10
			start_node = self.go_up_n(n-1)
			dif_start = start_node.dif
			dif_now = self.dif
			if n!=1: #no need to update
				if dif_now==dif_start:
					return True
				else:
					return False
			one_before = self.go_up_n(1)
			
			t1 = dateutil.parser.parse(json.loads(ten_before.block_hash['block'])['timestamp'])
			t2 = dateutil.parser.parse(json.loads(one_before.block_hash['block'])['timestamp'])
			third_minute = dateutil.parser.relativedelta.datetime.timedelta(minutes=30)
			two_hour = dateutil.parser.relativedelta.datetime.timedelta(hours=2)
			
			
			if t2-t1< third_minute:	 #increase case
				if dif_now== dif_before+1:
					return True
			elif t2-t1 > two_hour: # decrease case
				if dif_now == dif_before-1:
					return True
			else: # maintain case
				#print(self.dif,self.go_up_n(1).dif,self.go_up_n(2).dif,self.go_up_n(3).dif,self.go_up_n(4).dif,self.go_up_n(5).dif,self.go_up_n(6).dif,self.go_up_n(7).dif,self.go_up_n(8).dif,self.go_up_n(9).dif,dif_before,self.depth)
				#print(t2-t1)
				if dif_now==dif_before:
					return True
			#print("not any case?",dif_now,dif_before,ten_Before.depth,self.depth)
			return False
		return False
	def go_up_n(self,n):
		if n<0:
			return False
		if n==0:
			return self
		else:
			return self.parent_ptr.go_up_n(n-1)
import sys
def main_routine(target_hash):
	data = get_p2p_msgs()
	chain_tree = Block_chain(data[0])
	for d in data[1:]:
		res = chain_tree.add(d)
	print_json_output(chain_tree.get_target_hash(target_hash)[-1].roots)
	return chain_tree	

if __name__=="__main__":
	# print(sys.argv)
	main_routine(sys.argv[1])
	
