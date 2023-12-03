from sqlalchemy.orm import Session
from fastapi import Depends, FastAPI, HTTPException, status , File, UploadFile, requests,responses,Response,Request

from . import models, schemas,main
import bcrypt

def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()
def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()
def get_user_by_name(db: Session, username: str):
    return db.query(models.User).filter(models.User.Username == username).first()
def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')
def create_user(db: Session, user: schemas.UserCreate):
    try:
        fake_hashed_password = hash_password(user.password)
        new_user = models.User(Username=user.Username, email=user.email, hashed_password=fake_hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return user
    except Exception as e:
        print(f"Error creating user: {e}")
        # You may want to log the error or handle it appropriately
        raise
