from digital_signature import *
from data_structure import *
from datetime import datetime
#input : byte stream
#output : incremented byte stream
def stream_increment(input_stream):
	int_str = int.from_bytes(input_stream,'big')
	int_str +=1
	incr_bstr = int_str.to_bytes((int_str.bit_length()+7)//8,'big')
	return incr_bstr

#input : reward(public key) , difficulty( hex),parent, transactions( list of valid transaction sig)
#output: block hash
def mining(reward,difficulty,parent,transactions):
	nonce = ''
	time_now = datetime.utcnow().isoformat()
	block = {
		"type":"block",
		"transactions":transactions,
		"timestamp": time_now,
		"reward":reward,
		"difficulty":difficulty,
		"nonce":nonce,
		"parent":parent
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
		"block":json.dumps(block),
		"hash": hash_cal
	}

	return block_hash
