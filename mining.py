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
	if (random.randint(0,10000)>9999):
		print(incr_str)
	return incr_str

#input : reward(public key) , difficulty( hex),parent(hex string fixed size 18bit), transactions( list of valid transaction sig)
#output: block hash
def mining(reward,difficulty,parent,transactions):
	nonce = '0'
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
	#hash calculation
	while(True):
		block['nonce'] = nonce
		block['timestamp'] = time_now
		hash_cal = int(hash_bitcoin(json.dumps(block)),16)
		if hash_cal < target :
			break
		else:
			nonce = stream_increment(nonce)
			time_now = datetime.utcnow().isoformat()
	block_hash = {
		"type":"block_hash",
		"block":json.dumps(block).encode(),
		"hash": hash_cal.zfill(128)
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
	print("current difficulty : ",dif)
	txns = []
	block_new = mining(get_modulus(keys),dif,parent_block_hash_value,txns)	
	post_p2p_msgs(block_new)
	return

def send_my_money_to_get_grade():
	t = main_routine('11111111111')
	parent_block_hash_value = hex(t.get_longest()[-1].hash)[2:].zfill(128)
	keys = pksk_read('pksk')
	dif = next_dif(t)
	#keys_grade = pksk_read('grade_key')
	txn = json.loads(make_transaction_hash(get_modulus(keys),keys_grade()))
	block_new = mining(get_modulus(keys),dif,parent_block_hash_value,[txn])
	return


def make_transaction_hash(publickey_from,publickey_to,amount,time,parent,secretkey_from):
	time_now = datetime.utcnow().isoformat()
	dict_ = OrderedDict()
	dict_['type'] = "transaction"
	dict_['from'] = publickey_from
	dict_['to'] = pulbickey_to
	dict_['timestamp'] = time
	dict_['amount'] = amount
	dict_['parent'] = parent.zfill(128)
	res = mk_transaction_sign(dict_,secretkey_from)
	return res
def make_transaction(transaction,sk):
	dict_ = OrderedDict()
	dict_['type'] = "transaction_sign"
	dict_['transaction'] = transaction
	dict_['sign'] = sign(sk,hash_bitcoin(json.dumps(transaction)))
	return dict_
