#1 How you implemented data structure

1) get_p2p_msgs()
������ web server url�� ���ؼ� data�� �ҷ����� �Ľ��մϴ�.
data list�� return�մϴ�
2) validation part
�ΰ��� ��Ʈ�� ���� �� �ֽ��ϴ�. type check validation�� ���� ��ȿ�� ���� Ȯ���ϴ� validation
type error�� �ϵ� ���� ���� �� �κ����� ������ �����߽��ϴ�.
3) longest chain select 
data block���� tree�� ������ �����鼭 ���� ����� ��� �߰��� �� �ִ��� Ȯ���մϴ�.
�ϼ��� Ʈ������ ���� �� chain�� return�մϴ�. target hash�� �־����ٸ� �־��� target hash���� ��
���� �� chain�� �����մϴ�.

#2 How to build your project
digital_signature.py

1) python3�� ����մϴ�
2) python3 data_structure.py [hash in hex string] > [filename]
ex) python3 data_structure.py 'cafebene' > balance.json


