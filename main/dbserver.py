import sqlite3
 
conn = sqlite3.connect("fingerprint.db")
 
cursor = conn.cursor()
 
### creating tables
# ID_user, template_data, signup_date expressed in UNIX time
cursor.execute("""CREATE TABLE fingerprint
                  (ID_user integer, fingerprint_data blob, fingerprint_scan_date int) 
               """)

# ID_user, user_name, group
# group works as linux privileges work, in this case:
# 0111 means first number is admin, second is group 1, third is group 2, fourth is group 3...
# So this user is not admin, but is a user of the three first groups
cursor.execute("""CREATE TABLE user
                  (ID_user integer, user_name text, group int) 
               """)

# ID_FPS, signup_date (unix time), location, group_access
# group_access allows groups to use the FPS or not. If a user is member of a group
# with access 1, he will be allowed access.
# As special use, a group with access 2 won't be allowed access not matter what,
# even if the user is in a different group with acess 1
cursor.execute("""CREATE TABLE fps
                  (ID_FPS integer, signup_date int, location text, group_access int) 
               """)

# ID_log, ID_user, ID_FPS, date, access_granted
# Will save access_log, including user and FPS used, date, and if access was allowed or not
cursor.execute("""CREATE TABLE log
                  (ID_log int, ID_user int, ID_FPS int, date int, access_granted int) 
               """)
