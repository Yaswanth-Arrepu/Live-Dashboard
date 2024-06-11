import sqlite3
def init_db():
    with sqlite3.connect('example.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                gender TEXT,
                phone_number TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS departments (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS production (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                department_id INTEGER,
                date TEXT,
                produced_quantity INTEGER,
                FOREIGN KEY (department_id) REFERENCES departments(id)
            )
        ''')
        conn.commit()

