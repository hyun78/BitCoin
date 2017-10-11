#1 How you implemented digital signature

#1-1 generateKey(keysize)
Used PyCrpyto library to generate public and secret key in RSA-2048
Crypto.PulbicKey.RSA.generate(keysize)를 사용하여 PublicExponent(e), PrivateExponent(d), Modulus(N)를 생성
생성된 e,d,N 은 integer이므로 이를 hex값으로 변환하여
sk = d,N
pk = e,N
로 sk,pk를 생성함.

#1-2 sign(sk,msg)
hashlib을 사용하여 주어진 msg를 sha512 해시 함수에 넣음.
해시된 메시지를 sk를 사용해 RSA 2048로 암호화하고, 이를 sig라고 함.
sig를 return함.

#1-3 verify(pk,msg,sig)
받은 메시지를 hashlib을 사용하여 sha512로 해싱함
또한 sig를 pk를 사용하여 복호화함
해시된 메시지와 복호화된 메시지가 동일한지 확인하고, 동일하면 True, 아니면 False를 반환함

#2 How to build your project
digital_signature.py

1) python3를 사용합니다
2) PyCrypto 라이브러리를 설치합니다 (pip3 install PyCrypto)
3) key.json, key.payload가 같은 폴더에 있는 상태에서 python3 digital_signature.py 를 입력합니다.

