import sys
import sqlite3
 
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

with open("template.dat", 'rb') as output:
	buffer = output.read(498)
	user = (1, 'David López Chica', 1, buffer, 0)
	cursor.execute("INSERT INTO users VALUES (?,?,?,?,?)", user)
	conn.commit()
	output.close()
			   
conn.close()
sys.exit()
