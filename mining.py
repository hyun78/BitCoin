from digital_signature import *
from data_structure import *
from datetime import datetime
import base36
import random
#input : base 36 string
#output : incremented base 36 string
def stream_increment(input_str):
	int_str = base36.loads(input_str)
	int_str +=1
	incr_str = base36.dumps(int_str)
	return incr_str

def gen_random_string(n):
	s = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(n)) 
	return s
def generate_block_string_with_nonce(block_str,nonce):
	st1 = block_str.split('nonce')
	try:
		st3 = '{}"nonce": "{}",{}'.format(st1[0][:-1],nonce,st1[1].split(',')[1])
	except:
		st3 = '{}"nonce": "{}",{}'.format(st1[0][:-1],nonce,st1[1])
	return st3

def test_new(block_hash):
	nonce = gen_random_string(128)
	block1 = json.dumps(block_hash)
	block1 = generate_block_string_with_nonce(block1,nonce)
	block_hash['nonce'] = nonce
	block2 = json.dumps(block_hash)
	print(block1,"\n",block2,block1==block2)
	return
def teset2(block_hash):
	block_str = json.dumps(block_hash)
	target = pow(2,512-20)
	for i in range(100):
		nonce = gen_random_string(128)
		block_str = generate_block_string_with_nonce(block_str,nonce)
		hash_cal = int(hash_bitcoin(block_str),16)
		if hash_cal < target :
			break
	return


#input : reward(public key) , difficulty( hex),parent(hex string fixed size 18bit), transactions( list of valid transaction sig)
#output: block hash
def mining(reward,difficulty,parent,transactions):
	n = 128
	nonce = gen_random_string(n)
	time_now = datetime.utcnow().isoformat()
	block = {
		"type":"block",
		"transactions":transactions,
		"timestamp": time_now,
		"reward":reward,
		"difficulty":difficulty,
		"nonce":nonce,
		"parent":parent.zfill(128)
	}
	difficulty = int(block['difficulty'],16)
	target = pow(2,512-20-difficulty)
	block_str = json.dumps(block)
	#hash calculation
	while(True):
		block_str = generate_block_string_with_nonce(block_str,nonce)
		hash_cal = int(hash_bitcoin(block_str),16)
		if hash_cal < target :
			break
		else:
			nonce = gen_random_string(n)
			
	block_hash = {
		"type":"block_hash",
		"block":block_str,
		"hash": hex(hash_cal)[2:].zfill(128)
	}

	return block_hash
def next_dif(chain):
	dif = 0
	last_one = chain[-1]
	if last_one.depth%10==0:#바뀌는경우
		
		start_node = last_one.go_up_n(9)
		dif_start = start_node.dif
		
		t1 = dateutil.parser.parse(json.loads(start_node.block_hash['block'])['timestamp'])
		t2 = dateutil.parser.parse(json.loads(last_one.block_hash['block'])['timestamp'])

		third_minute = dateutil.parser.relativedelta.datetime.timedelta(minutes=30)
		two_hour = dateutil.parser.relativedelta.datetime.timedelta(hours=2)		
		if t2-t1<third_minute:
			dif =  dif_start+1
		elif t2-t1>two_hour:
			dif = dif_start-1
		else:
			dif = dif_start
	else:
		dif = last_one.dif
	return dif

def mine_only():
	t = main_routine('11111111111')
	main_chain = t.get_longest()
	parent_block_hash_value = hex(main_chain[-1].hash)[2:].zfill(128)
	keys = pksk_read('pksk')
	dif = hex(next_dif(main_chain))[2:]
	print("current difficulty : ",dif,main_chain[-1].depth)
	txns = []
	block_new = mining(get_modulus(keys),dif,parent_block_hash_value,txns)	
	post_p2p_msgs(block_new)
	return

def send_my_money_to_get_grade():
	t = main_routine('11111111111')
	main_chain = t.get_longest()
	parent_block_hash_value = hex(main_chain[-1].hash)[2:].zfill(128)
	keys = pksk_read('pksk_2000')
	dif = next_dif(main_chain)
	roots = main_chain[-1].roots
	amt = roots[get_modulus(keys)]
	#keys_grade = pksk_read('grade_key')
	key_file = open('20140708.pub','r')
	keys_grade = key_file.readline()
	key_file.close()
	print("owner : ",get_modulus(keys),"\n amout : ",amt)
	if amt<=50:
		print("not enough amount")
		return False
	txn = (make_transaction_hash(get_modulus(keys),keys_grade,hex(amt-50)[2:],parent_block_hash_value,get_secret_key_from(keys)))
	block_new = mining(get_modulus(keys),hex(dif)[2:],parent_block_hash_value,[txn])
	post_p2p_msgs(block_new)
	return True
def post_txns_2000():
	t = main_routine('11111111111')
	main_chain = t.get_longest()
	parent_block_hash_value = hex(main_chain[-1].hash)[2:].zfill(128)
	keys = pksk_read('pksk_2000')
	dif = next_dif(main_chain)
	roots = main_chain[-1].roots
	amt = roots[get_modulus(keys)]
	key_file = open('20140708.pub','r')
	keys_grade = key_file.readline()
	key_file.close()
	print("owner : ",get_modulus(keys),"\n amout : ",amt)
	if amt<=50:
		print("not enough amount")
		return False
	txn = (make_transaction_hash(get_modulus(keys),keys_grade,hex(amt-50)[2:],parent_block_hash_value,get_secret_key_from(keys) ))
	post_p2p_msgs(txn)
	
	return True


def make_transaction_hash(publickey_from,publickey_to,amount,parent,secretkey_from):
	time_now = datetime.utcnow().isoformat()
	dict_ = OrderedDict()
	dict_['type'] = "transaction"
	dict_['from'] = publickey_from
	dict_['to'] = publickey_to
	dict_['timestamp'] = time_now
	dict_['amount'] = amount
	dict_['parent'] = parent.zfill(128)
	res = make_transaction(dict_,secretkey_from)
	return res
def make_transaction(transaction,sk):
	dict_ = OrderedDict()
	dict_['type'] = "transaction_sign"
	dict_['transaction'] = transaction
	dict_['sign'] = sign(sk,hash_bitcoin(json.dumps(transaction)))
	return dict_
if __name__=="__main__":
	while True:
			mine_only()
