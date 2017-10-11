#1 How you implemented digital signature

#1-1 generateKey(keysize)
Used PyCrpyto library to generate public and secret key in RSA-2048
Crypto.PulbicKey.RSA.generate(keysize)�� ����Ͽ� PublicExponent(e), PrivateExponent(d), Modulus(N)�� ����
������ e,d,N �� integer�̹Ƿ� �̸� hex������ ��ȯ�Ͽ�
sk = d,N
pk = e,N
�� sk,pk�� ������.

#1-2 sign(sk,msg)
hashlib�� ����Ͽ� �־��� msg�� sha512 �ؽ� �Լ��� ����.
�ؽõ� �޽����� sk�� ����� RSA 2048�� ��ȣȭ�ϰ�, �̸� sig��� ��.
sig�� return��.

#1-3 verify(pk,msg,sig)
���� �޽����� hashlib�� ����Ͽ� sha512�� �ؽ���
���� sig�� pk�� ����Ͽ� ��ȣȭ��
�ؽõ� �޽����� ��ȣȭ�� �޽����� �������� Ȯ���ϰ�, �����ϸ� True, �ƴϸ� False�� ��ȯ��

#2 How to build your project
digital_signature.py

1) python3�� ����մϴ�
2) PyCrypto ���̺귯���� ��ġ�մϴ� (pip3 install PyCrypto)
3) key.json, key.payload�� ���� ������ �ִ� ���¿��� python3 digital_signature.py �� �Է��մϴ�.

