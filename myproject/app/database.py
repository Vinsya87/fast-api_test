import sqlite3


# Создание таблиц
def create_tables():
    connection = sqlite3.connect('mydatabase.db')
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            hashed_password TEXT
        )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT,
        author_id TEXT,
        FOREIGN KEY (author_id) REFERENCES users (username)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            user_id TEXT,
            post_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (username),
            FOREIGN KEY (post_id) REFERENCES posts (id),
            UNIQUE (user_id, post_id)
        )
    """)

    connection.commit()
    connection.close()