#1 How you implemented data structure

1) get_p2p_msgs()
합의한 web server url을 통해서 data를 불러오고 파싱합니다.
data list를 return합니다
2) validation part
두가지 파트로 나눌 수 있습니다. type check validation과 실제 유효한 것을 확인하는 validation
type error가 하도 많이 나서 두 부분으로 나누어 구현했습니다.
3) longest chain select 
data block들을 tree로 저장해 나가면서 다음 블록이 어디에 추가될 수 있는지 확인합니다.
완성된 트리에서 가장 긴 chain을 return합니다. target hash가 주어진다면 주어진 target hash까지 중
가장 긴 chain을 리턴합니다.

#2 How to build your project
digital_signature.py

1) python3를 사용합니다
2) python3 data_structure.py [hash in hex string] > [filename]
ex) python3 data_structure.py 'cafebene' > balance.json


