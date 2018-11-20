#!/usr/bin/env python

import sys
import sqlite3
import socket
from datetime import datetime
 
conn = sqlite3.connect("fingerprint.db")
 
cursor = conn.cursor()
 
### creating tables


# ID_user, user_name, group, template_data, signup_date expressed in UNIX time
# group works as linux privileges work, in this case:
# 0111 means first number is admin, second is group 1, third is group 2, fourth is group 3...
# So this user is not admin, but is a user of the three first groups
cursor.execute("""CREATE TABLE IF NOT EXISTS users
                  (ID_user INTEGER PRIMARY KEY, user_name TEXT NOT NULL,
                  group_user INTEGER NOT NULL, fingerprint_data BLOB NOT NULL,
                  fingerprint_scan_date INTEGER NOT NULL) 
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


### inserting example data

#with open("template.dat", 'rb') as output:
#	buffer = output.read(498)
#	user = (None, 'David López Chica', 1, buffer, 0)
#	cursor.execute("INSERT INTO users VALUES (?,?,?,?,?)", user)
#	conn.commit()
#	output.close()


HOST = ''	# Symbolic name meaning all available interfaces
PORT = 40444	# Arbitrary non-privileged port

# Listeners

def enroller_listener(d, s):

	data = d[0]
	addr = d[1]
	length = len(d[0])
	
	if data[4] == 17: # 0x11 == 17(Enrolling)
		
		s.sendto(bytes([1, 219, 0, 1, 170]), addr) # 0x01 0xDB 0x00 0x01 0xAA == 1 219 0 1 170 (AA okay)
		return

	elif data[4] == 29: # 0x1D == 29 (Sending data)
	
		checksum_reported = 0
		checksum_data = 256 # Data packet starts with 0x5A + 0xA5 + 0x00 + 0x01 = 256
		fingerprint = bytearray()
		
		for x in range(0,8):
		
			# receive data from client (data, addr)
			d = s.recvfrom(64)
			data = d[0]
			addr = d[1]
			length = len(d[0])
		
			if not data:
				break
		
			print(data.hex())
		
			if x == 7:
				checksum_reported = data[length-2] + data[length-1]*256 # Little endian
				print('Checksum calculated = ' + str(checksum_reported))
				for i in range(0,length-2):
					checksum_data += data[i]
					fingerprint.append(data[i])

			else:
				for i in range(0,length):
					checksum_data += data[i]
					fingerprint.append(data[i])

			print('Checksum reported in the data was: ' + str(checksum_data%65536))

		user = (None, 'David López Chica', 1, fingerprint, datetime.now())
		cursor.execute("INSERT INTO users VALUES (?,?,?,?,?)", user)
		conn.commit()

		return
	
	else:
		
		s.sendto(bytes([1, 219, 0, 1, 238]), addr) # 0x01 0xDB 0x00 0x01 0xEE == 1 219 0 1 238 (EE error)
		return
	
def scanner_listener(d, s):
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
except (socket.error, msg):
	print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()
	
print('Socket bind complete')

while 1:

	# receive data from client (data, addr)
	d = s.recvfrom(64)
	data = d[0]
	addr = d[1]
	
	if not data or len(d[0])<5 or data[0] != 1: # First byte has always to be 0x01
		break

	listener = code_interpreter(data[1])
	if listener == 'error':
		s.sendto(bytes([1, 219, 0, 1, 238]), addr) # 0x01 0xDB 0x00 0x01 0xEE == 1 219 0 1 238 (EE error)
		break
	
	print(data.hex())
	listener(d, s)
	
s.close()
