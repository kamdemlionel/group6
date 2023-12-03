from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    Username: str
    email: str 
    full_name: str | None = None
    disabled: bool | None = None


# class UserInDB(User):
#     hashed_password: str


# class ItemBase(BaseModel):
#     title: str
#     description: str | None = None


# class ItemCreate(ItemBase):
#     pass


# class Item(ItemBase):
#     id: int
#     owner_id: int

#     class Config:
#         from_attributes = True


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    Username:str
    email:str
    password: str


# class User(UserBase):
#     id: int
#     is_active: bool
#     # items: list[Item] = []

    class Config:
        from_attributes = True

        