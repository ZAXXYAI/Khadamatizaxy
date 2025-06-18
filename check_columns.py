import sqlite3

conn = sqlite3.connect('database/db.sqlite')
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()

for idx, col in enumerate(columns):
    print(f"{idx}: {col[1]}")

conn.close()
