
import sqlite3
from datetime import datetime, timedelta

from app.database import create_tables
from app.models import Post, Token, User
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = "26964913ad90fa1733daa4089c59311f74262e45791c7db320fd101ca6cbb5a1"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_db():
    connection = sqlite3.connect('mydatabase.db', check_same_thread=False)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user_by_username(username: str, db: sqlite3.Connection):
    cursor = db.cursor()
    query = 'SELECT * FROM users WHERE username=?'
    result = cursor.execute(query, (username,))
    return result.fetchone()


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def authenticate_user(username: str, password: str, db: sqlite3.Connection):
    user = get_user_by_username(username, db)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: sqlite3.Connection = Depends(get_db)
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user["username"]}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/users/register")
def register_user(user: User, db: sqlite3.Connection = Depends(get_db)):
    username = user.username
    password = pwd_context.hash(user.password)

    db_user = get_user_by_username(username, db)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    cursor = db.cursor()
    query = 'INSERT INTO users (username, password, hashed_password) VALUES (?, ?, ?)'
    cursor.execute(query, (username, user.password, password))
    db.commit()
    return {"message": "User registered successfully"}


@app.get("/users/me")
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return {"username": username}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


@app.get("/posts/{post_id}")
def get_post(post_id: int, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    query = 'SELECT * FROM posts WHERE id=?'
    result = cursor.execute(query, (post_id,))
    post = result.fetchone()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return {"post_id": post[0], "title": post[1], "content": post[2], "author_id": post[3]}


@app.post("/posts")
def create_post(
    post: Post,
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    ):
    author_id = current_user["username"]
    cursor = db.cursor()
    query = 'INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)'
    cursor.execute(query, (post.title, post.content, author_id))
    db.commit()
    return {"message": "Post created successfully"}


@app.put("/posts/{post_id}")
def update_post(
    post_id: int,
    post: Post,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
    ):
    cursor = db.cursor()
    query = 'SELECT * FROM posts WHERE id=?'
    result = cursor.execute(query, (post_id,))
    existing_post = result.fetchone()
    if not existing_post:
        raise HTTPException(status_code=404, detail="Post not found")
    if existing_post["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="Only the creator can update the post")
    update_query = 'UPDATE posts SET title=?, content=? WHERE id=?'
    cursor.execute(update_query, (post.title, post.content, post_id))
    db.commit()
    return {"message": "Post updated successfully"}



@app.delete("/posts/{post_id}")
def delete_post(
    post_id: int,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db),
    ):
    cursor = db.cursor()
    query = 'SELECT * FROM posts WHERE id=?'
    result = cursor.execute(query, (post_id,))
    existing_post = result.fetchone()
    if not existing_post:
        raise HTTPException(status_code=404, detail="Post not found")
    if existing_post["author_id"] != current_user["username"]:
        raise HTTPException(status_code=403, detail="Only the creator can delete the post")

    delete_query = 'DELETE FROM posts WHERE id=?'
    cursor.execute(delete_query, (post_id,))
    db.commit()
    return {"message": "Post deleted successfully"}



@app.post("/posts/{post_id}/like")
def like_post(
    post_id: int,
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict = Depends(get_current_user)
    ):
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    cursor = db.cursor()
    query = 'SELECT * FROM posts WHERE id=?'
    result = cursor.execute(query, (post_id,))
    post = result.fetchone()
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )
    if current_user["username"] == post["author_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot like your own post"
        )
    query = 'SELECT * FROM likes WHERE user_id=? AND post_id=?'
    result = cursor.execute(query, (current_user["username"], post_id))
    like = result.fetchone()
    if like:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You have already liked this post"
        )
    query = 'INSERT INTO likes (user_id, post_id) VALUES (?, ?)'
    cursor.execute(query, (current_user["username"], post_id))
    db.commit()

    return {"message": "Post liked successfully"}



@app.post("/posts/{post_id}/dislike")
def dislike_post(
    post_id: int,
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict = Depends(get_current_user)
    ):
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    cursor = db.cursor()
    query = 'SELECT * FROM posts WHERE id=?'
    result = cursor.execute(query, (post_id,))
    post = result.fetchone()
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )
    if current_user["username"] == post["author_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot dislike your own post"
        )
    query = 'SELECT * FROM likes WHERE user_id=? AND post_id=?'
    result = cursor.execute(query, (current_user["username"], post_id))
    like = result.fetchone()
    if not like:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You have not liked this post"
        )
    query = 'DELETE FROM likes WHERE user_id=? AND post_id=?'
    cursor.execute(query, (current_user["username"], post_id))
    db.commit()

    return {"message": "Post disliked successfully"}


# Создание таблиц при запуске приложения
create_tables()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
