#!/usr/bin/env python

import sys
import os
import sqlite3
import socket
import time
from datetime import datetime
from SuperFastHash import SuperFastHash as SFHash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = ''	# Symbolic name meaning all available interfaces
PORT = 40444	# Arbitrary non-privileged port
AES_KEY = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6])
aesgcm = AESGCM(AES_KEY)
conn = sqlite3.connect("fingerprint.db")
cursor = conn.cursor()


### creating tables

# ID_user, user_name, group, template_data, template_hash, signup_date expressed in UNIX time
# group works as linux privileges work, in this case:
# 0111 means first number is admin, second is group 1, third is group 2, fourth is group 3...
# So this user is not admin, but is a user of the three first groups
cursor.execute("""CREATE TABLE IF NOT EXISTS users
                  (ID_user INTEGER PRIMARY KEY, user_name TEXT NOT NULL,
                  group_user INTEGER NOT NULL, fingerprint_data BLOB NOT NULL,
                  fingerprint_hash INTEGER NOT NULL, fingerprint_scan_date INTEGER NOT NULL)
               """)

# ID_FPS, signup_date (unix time), location, group_access
# group_access allows groups to use the FPS or not. If a user is member of a group
# with access 1, he will be allowed access.
# As special use, a group with access 2 won't be allowed access not matter what,
# even if the user is in a different group with acess 1
cursor.execute("""CREATE TABLE IF NOT EXISTS fps
                  (ID_FPS INTEGER PRIMARY KEY, signup_date INTEGER NOT NULL,
                  location TEXT NOT NULL, group_access INTEGER NOT NULL)
               """)

# ID_log, ID_user, ID_FPS, date, access_granted
# Will save access_log, including user and FPS used, date, and if access was allowed or not
cursor.execute("""CREATE TABLE IF NOT EXISTS log
                  (ID_log INTEGER PRIMARY KEY AUTOINCREMENT, ID_user INTEGER NOT NULL,
                  ID_FPS INTEGER NOT NULL, date INTEGER NOT NULL,
                  access_granted INTEGER NOT NULL,
                  CONSTRAINT fk_user FOREIGN KEY (ID_user)
                  REFERENCES users(ID_user)
                  CONSTRAINT fk_fps FOREIGN KEY (ID_FPS)
                  REFERENCES fps(ID_FPS))
               """)


# Listeners

def enroller_listener(data, addr, s):

	if data[4] == 17: # 0x11 == 17(Enrolling)

		s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 170])), addr) # 0x01 0xDB 0x00 0x01 0xAA == 1 219 0 1 170 (AA okay)
		return

	elif data[4] == 29: # 0x1D == 29 (Sending data)

		checksum_reported = 0
		checksum_data = 256 # Data packet starts with 0x5A + 0xA5 + 0x00 + 0x01 = 256
		fingerprint = bytearray()

		try:
			# receive data from client (data, addr)
			d = s.recvfrom(1024)
		except socket.timeout:
			return

		data = d[0]
		addr = d[1]

		if not data or len(data) < 28:
			return

		try:
			# Decrypt the packet
			nonce = data[0:12]
			message_withtag = data[12:]
			data = aesgcm.decrypt(nonce, message_withtag, None) # TO-DO fail check
		except Exception: # All the possible exceptions should be safely ignored
			print("Failed decryption at fingerprint upload.")
			return

		print(data.hex())
		length = len(data)

		for i in range(length-2):
			checksum_data += data[i]
			fingerprint.append(data[i])

		print('Checksum calculated up to this point = ' + str(checksum_data%65536))
		checksum_reported = data[length-2] + data[length-1]*256 # Little endian
		print('Checksum reported from the FPS = ' + str(checksum_reported))

		# TO-DO: Fail condition when checksum is wrong
		user = (None, 'David López Chica', 1, fingerprint, SFHash(fingerprint), datetime.now())
		cursor.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", user)
		conn.commit()

		return

	else:

		s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 238])), addr) # 0x01 0xDB 0x00 0x01 0xEE == 1 219 0 1 238 (EE error)
		return

def scanner_listener(data, addr, s):

	if data[4] == 34: # 0x22 == 34(SyncDB)

		s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 170])), addr) # 0x01 0xDB 0x00 0x01 0xAA == 1 219 0 1 170 (AA okay)
		return

	elif data[4] == 48: # 0x30 == 48(Requesting fingerprint)

		fingerprint_hash_requested = int.from_bytes([data[5], data[6], data[7], data[8]], byteorder='big')
		cursor.execute("SELECT fingerprint_data FROM users WHERE fingerprint_hash=?", (str(fingerprint_hash_requested),))
		fingerprint_data = cursor.fetchone()[0]
		s.sendto(encrypt_bytes(fingerprint_data), addr)
		return

	elif data[4] == 93: # 0x5D == 93(Requesting partial DDBB download)

		num_enrolled = data[5]
		num_packets_sent = num_enrolled//128
		if num_enrolled%128 > 0:
			num_packets_sent += 1

		cursor.execute("SELECT fingerprint_hash FROM users")
		ddbb_hashes = []
		for row in cursor:
			ddbb_hashes.append(row[0])
		print("ddbb_hashes")
		print(ddbb_hashes)

		deletion_hashes = []

		for packet in range(num_packets_sent):

			try:
				# receive data from client (data, addr)
				d = s.recvfrom(1024)
			except socket.timeout:
				return

			data = d[0]
			addr = d[1]

			if not data or len(data) < 28:
				return

			try:
				# Decrypt the packet
				nonce = data[0:12]
				message_withtag = data[12:]
				data = aesgcm.decrypt(nonce, message_withtag, None) # TO-DO fail check
			except Exception: # All the possible exceptions should be safely ignored
				print("Failed decryption at hash list sync check.")
				return

			print(data.hex())

			if packet == num_packets_sent-1:
				num_fingerprints = num_enrolled%128
				if num_fingerprints == 0:
					num_fingerprints = 128
			else:
				num_fingerprints = 128

			for fingerprint in range(num_fingerprints):
				fingerprint_hash = int.from_bytes([data[fingerprint*4], data[fingerprint*4 + 1], data[fingerprint*4 + 2], data[fingerprint*4 + 3]], byteorder='big')
				if fingerprint_hash in ddbb_hashes:
					ddbb_hashes.remove(fingerprint_hash)
					print("Exists: " + str(fingerprint_hash))
				else:
					deletion_hashes.append(packet*128 + fingerprint) # Gives the fingerprint_num to delete, instead of the hash
					print("Remove fingerprint "+ str(packet*128 + fingerprint) + ": " + str(fingerprint_hash))

		print("Update list...")
		print(ddbb_hashes)

		# Delete list
		if len(deletion_hashes) > 0:
			s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 222, len(deletion_hashes)])), addr)
			time.sleep(1)
			print(bytes(deletion_hashes))
			s.sendto(encrypt_bytes(bytes(deletion_hashes)), addr)
			time.sleep(1)

		# Addition list
		if len(ddbb_hashes) > 0:
			s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 173, len(ddbb_hashes)])), addr)
			time.sleep(1)
			addition_hashes = bytearray()
			for fingerprint in ddbb_hashes:
				addition_hashes.extend(fingerprint.to_bytes(4, byteorder='big'))
			print(addition_hashes)
			s.sendto(encrypt_bytes(addition_hashes), addr)
			time.sleep(1)

		# End sync process
		s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 13, 0])), addr)
		return

	elif data[4] == 253: # 0xFD = 253(Requesting full DDBB download)

		num_additions = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
		if num_additions == 0:
			s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 13, 0])), addr)
			return

		s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 173, num_additions])), addr)
		time.sleep(1)

		cursor.execute("SELECT fingerprint_hash FROM users")
		hash_data = bytearray()
		for row in cursor:
			hash_data += bytearray(row[0].to_bytes(4, byteorder="big"))
		s.sendto(encrypt_bytes(hash_data), addr)
		time.sleep(1)

		# End sync process
		s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 13, 0])), addr)
		return

	else:

		s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 238])), addr) # 0x01 0xDB 0x00 0x01 0xEE == 1 219 0 1 238 (EE error)
		return

listener_switcher = {
#	219: server_listener, # DB
	238: enroller_listener, # EE
	253: scanner_listener # FD
}

def code_interpreter(argument):
    # Get the function from switcher dictionary
    func = listener_switcher.get(argument, "error")
    # Return the function
    return func

def encrypt_bytes(data):
	nonce = os.urandom(12)
	message_withtag = aesgcm.encrypt(nonce, data, None)
	return nonce+message_withtag
	
# Datagram (udp) socket
try :
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	print('Socket created')
except (socket.error, msg):
	print('Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()

# Bind socket to local host and port
try:
	s.bind((HOST, PORT))
	s.settimeout(5)
except (socket.error, msg):
	print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()

print('Socket bind complete')

while 1:

	try:
		# receive data from client (data, addr)
		d = s.recvfrom(1024)
	except socket.timeout:
		continue

	data = d[0]
	addr = d[1]

	if not data or len(data) < 28:
		continue

	try:
		# Decrypt the packet
		nonce = data[0:12]
		message_withtag = data[12:]
		data = aesgcm.decrypt(nonce, message_withtag, None) # TO-DO fail check
	except Exception: # All the possible exceptions should be safely ignored
		print("Failed decryption at initial communication.")
		continue

	print(data.hex())

	if data[0] == 1 and len(data) >= 5: # First byte has always to be 0x01
		listener = code_interpreter(data[1])
		if listener == 'error':
			s.sendto(encrypt_bytes(bytes([1, 219, 0, 1, 238])), addr) # 0x01 0xDB 0x00 0x01 0xEE == 1 219 0 1 238 (EE error)
		else:
			listener(data, addr, s)

s.close()
