from pydantic import BaseModel


# Определение моделей
class User(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class UserInDB(BaseModel):
    username: str
    hashed_password: str


class Post(BaseModel):
    title: str
    content: str
    author_id: str = None


class PostInDB(Post):
    id: int

    class Config:
        orm_mode = True


class Like(BaseModel):
    user_id: int
    post_id: int
