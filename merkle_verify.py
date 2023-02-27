import hashlib
import sys
import getopt
import os
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
# from Crypto.Signature import pkcs1_15 会导致验签失败，原因不明
# from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import pickle


# 计算文件的哈希值
def hash_file(filename, alg):
	hasher = hashlib.new(alg)                   # 根据输入的算法求哈希值
	with open(filename, 'rb') as f_h:
		buffer = f_h.read(65536)                        # 按 65536 字节读入，防止大文件爆内存
		while len(buffer) > 0:
			hasher.update(buffer)
			buffer = f_h.read(65536)
	return hasher.hexdigest()


# 递归构造 Merkle Hash 树
def build_merkle_tree(file_list_b, alg_b):
	if len(file_list_b) == 0:                           # 文件列表为空，退出
		print("fileListError")
		sys.exit()
	if len(file_list_b) == 1:                           # 文件列表长度为 1，仅 1 文件或叶子结点
		return hash_file(file_list_b[0], alg_b)
	middle = len(file_list_b) // 2                      # 二分递归
	left_child = build_merkle_tree(file_list_b[:middle], alg_b)
	right_child = build_merkle_tree(file_list_b[middle:], alg_b)
	if left_child and right_child:                      # 同时具有左右孩子，计算 Hash(Hash(l), Hash(r))
		hasher = hashlib.new(alg_b)
		hasher.update((left_child + right_child).encode('utf-8'))
		return hasher.hexdigest()
	elif left_child:
		return left_child
	else:
		return right_child


# 对根节点进行数字签名
def sign_root(root_hash_s):
	random_rsa = Random.new().read                      # 引入随机数
	rsa = RSA.generate(2048, random_rsa)                # 生成私钥
	public_key = rsa.publickey()                        # 生成公钥
	public_key_e = public_key.exportKey()               # 导出公钥
	signer = PKCS1_v1_5.new(rsa)
	# PKCS1_v1_5.sign(msg_hash: Hash)，参数类型为 Hash，hashlib.new -> _Hash，两者不可互用
	digest = MD5.new(root_hash_s.encode('utf-8'))
	signature = signer.sign(digest)                     # 签名
	return [public_key_e, signature]


# 验证签名并验证文件完整性
def verify_file_integrity(root_hash_v, file_list_v, alg_v, public_key_v, signature_v):
	# PKCS1_v1_5.sign(msg_hash: Hash)，参数类型为 Hash，hashlib.new -> _Hash，两者不可互用
	digest = MD5.new(root_hash_v.encode('utf-8'))
	public_key = RSA.importKey(public_key_v)            # 导入公钥
	pk = PKCS1_v1_5.new(public_key)
	if pk.verify(digest, signature_v):                  # 验证签名
		merkle_tree_root = build_merkle_tree(file_list_v, alg_v)
		if merkle_tree_root == root_hash_v:             # 验证 Merkle 根
			print("文件完整性未被破坏")
		else:
			print("文件完整性已被破坏")
	else:
		print("签名无效")


# 命令行参数及功能实现
def main(argv):
	file_list = []
	alg = "sha256"                                      # 算法默认选择 SHA256
	flag_m = False
	flag_v = False
	try:
		opts, args = getopt.getopt(argv, "hmva:f:d:p:", ["algorithm", "files", "directory", "proof"])
	except getopt.GetoptError:
		print("merkle_verify.py -m[-f <files list>, -d <directory>] -a <algorithm>\n")
		print("merkle_verify.py -v[-f <files list>, -d <directory>] -p <proof>\n")
		print("available algorithms:\n", hashlib.algorithms_available)
		sys.exit()

	for opt, arg in opts:
		if opt == "-h":
			print("merkle_verify.py -m[-f <files list>, -d <directory>] -a <algorithm>\n")
			print("merkle_verify.py -v[-f <files list>, -d <directory>] -p <proof>\n")
			print("available algorithms:\n", hashlib.algorithms_available)
			sys.exit()
		elif opt == "-m":
			flag_m = True
			continue
		elif opt == "-v":
			flag_v = True
			continue
		elif opt in ["-f", "--files"]:
			file_list = arg.split(',')
			continue
		elif opt in ["-d", "--directory"]:
			for file_path, dir_names, file_names in os.walk(arg):
				for filename in file_names:
					file_list.append(file_path + '/' + filename)
			continue
		elif opt in ["-p", "--proof"]:
			proof_in = arg
			alg = arg.split('.')[1]
			# with open(proof_in, "r") as f:
			# 	root_hash_in = ""
			# 	buffer = f.read(65536)
			# 	while len(buffer) > 0:
			# 		root_hash_in += buffer
			# 		buffer = f.read(65536)
			with open(proof_in, "rb") as f:
				root_hash_in = pickle.load(f)
			continue
		elif opt in ["-a", "--algorithm"]:
			alg = arg
			continue

	if flag_m:
		root_hash = build_merkle_tree(file_list, alg)
		[public_key, signature] = sign_root(root_hash)
		# with open("proof."+alg, "wb") as f:
		# 	f.write(root_hash)
		with open("proof."+alg, "wb") as f:
			pickle.dump([root_hash, public_key, signature], f)
			print('hash: ', root_hash)
		sys.exit()
	elif flag_v:
		verify_file_integrity(root_hash_in[0], file_list, alg, root_hash_in[1], root_hash_in[2])


if __name__ == "__main__":
	main(sys.argv[1:])

# python merkle_verify.py -m -f file1.txt
# python merkle_verify.py -v -f file1.txt -p proof.sha256
#
# python merkle_verify.py -m -f file1.txt,file2.txt,file3.txt
#
# python merkle_verify.py -m -d dir_1 -a md5
# python merkle_verify.py -v -d dir_1 -p proof.md5

