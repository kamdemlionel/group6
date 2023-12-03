from typing import List, Annotated,Optional
import os
import shutil

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import Depends, FastAPI, HTTPException, status , File, UploadFile, requests,responses,Response,Request,Form, Query
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from . import models
from starlette.responses import StreamingResponse
from tempfile import NamedTemporaryFile
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError
import json

from passlib.hash import bcrypt


import boto3
from botocore.exceptions  import NoCredentialsError

from . import crud, models, schemas, form
from .database import SessionLocal, engine
from .schemas import UserCreate, Token
from .crud import create_user, get_user, get_user_by_email
from .form import usercreateform


models.Base.metadata.create_all(bind=engine)

app = FastAPI()

template= Jinja2Templates(directory="template")
app.mount("/statics", StaticFiles(directory="statics"), name="statics")

SECRET_KEY = "c5e2a150cc85659b08ad2072dbd417d7e5691c6de2b5e6fd617427b62cf029b0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


from fastapi.responses import JSONResponse



    
@app.get('/', response_class=HTMLResponse)
async def home(request:Request, db: Session = Depends(get_db)):
    return template.TemplateResponse("index.html", {"request":request})

def authenticate_user(email: str, password: str,db: Session):
    user = get_user_by_email(email=email,  db=db)
    print(user)
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user



@app.post('/login', response_class=HTMLResponse)
async def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):    
    try:
        user = db.query(models.User).filter(models.User.email == email).first()

        if user is None:
            return template.TemplateResponse("index.html", {"request": request })
        else:
            if pwd_context.verify(password, user.hashed_password):
                data = {'sub': email}
                jwt_token= jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
                print(jwt_token)
                response =  RedirectResponse(url="/home", status_code=303)
                response.set_cookie(key="access_token", value=f"Bearer {jwt_token}", httponly=True)
                return response
            else:
                return template.TemplateResponse("index.html", {"request": request, "errors": "Incorrect password"})
    except Exception as e:
        return template.TemplateResponse("index.html", {"request": request, "errors": str(e)})

   
@app.get('/register', response_class=HTMLResponse)
async def signup(request:Request, db: Session = Depends(get_db)):
    return template.TemplateResponse("register.html", {"request":request})  


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        user = UserCreate(Username=username, email=email, password=password)
        create_user(user=user, db=db)
        return responses.RedirectResponse("/?alert=succesfullyegistered", status_code=status.HTTP_302_FOUND)
    except ValidationError as e:
        errors = [f"{error['loc'][0]}: {error['user already registered']}" for error in e.errors()]
        return template.TemplateResponse("register.html", {"request": request, "errors": errors})
    except Exception as e:
        errors = [str(e)]
        return template.TemplateResponse("register.html", {"request": request, "errors": errors})


@app.get("/users/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user



def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return payload




@app.get('/home', response_class=HTMLResponse)
async def home(request:Request, db: Session = Depends(get_db)):
    return template.TemplateResponse("home.html", {"request":request}) 
  
@app.get('/sucess', response_class=HTMLResponse)
async def home(request:Request, db: Session = Depends(get_db)):
    return template.TemplateResponse("sucess.html", {"request":request})   

@app.get('/success2', response_class=HTMLResponse)
async def home(request:Request, db: Session = Depends(get_db)):
    return template.TemplateResponse("success2.html", {"request":request}) 
@app.get('/success3', response_class=HTMLResponse)
async def home(request:Request, db: Session = Depends(get_db)):
    return template.TemplateResponse("success3.html", {"request":request}) 
@app.get('/list', response_class=HTMLResponse)
async def home(request:Request, db: Session = Depends(get_db)):
    return template.TemplateResponse("listfiles.html", {"request":request}) 


@app.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    return current_user

# AWS S3 Configuration
AWS_ACCESS_KEY = 'AKIA4PEEF2EOC2JVJGJ6'
AWS_SECRET_KEY = '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'
AWS_REGION = 'us-east-1'
S3_BUCKET_NAME = 'my-ssl-encryption'
KMS_KEY_ID='arn:aws:kms:us-east-1:857123180828:key/5e47d919-050b-4b59-b722-9597422ce81b'
s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION)
kms_client = boto3.client('kms', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION)


def encrypt_file(file_content, key_id):
    try:
        response = kms_client.encrypt(KeyId=key_id, Plaintext=file_content)
        return response['CiphertextBlob']
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="KMS credentials not available.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error encrypting file with KMS: {str(e)}")

@app.post("/encryptfile/")
async def create_encrypt_file( request:Request ,file: UploadFile = File(...)):
    try:
        content = await file.read()
        encrypted_content = encrypt_file(content, KMS_KEY_ID)

        # Upload the encrypted content to S3
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=file.filename, Body=encrypted_content)
        message = "File encrypted and stored in S3"
        return RedirectResponse(url="/success2", status_code=303)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")


def upload_to_s3(file, bucket_name, object_name):
    try:
        s3_client.upload_fileobj(file, bucket_name, object_name)
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="S3 credentials not available.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error uploading file to S3: {str(e)}")

@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile = File(...)):
    object_name = file.filename
    upload_to_s3(file.file, S3_BUCKET_NAME, object_name)
    return RedirectResponse(url="/success3", status_code=303)
def list_files_in_s3(bucket_name):
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        files = [obj['Key'] for obj in response.get('Contents', [])]
        return {"files": files}
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="S3 credentials not available.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing files in S3: {str(e)}")

app.get("/listfiles/", response_class=HTMLResponse)
async def list_files(request: Request):
    files_data = list_files_in_s3(S3_BUCKET_NAME)
    return template.TemplateResponse("listfiles.html", {"request": request, "files": files_data["files"]})

def download_from_s3(bucket_name, object_name):
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=object_name)
        return StreamingResponse(content=response['Body'].iter_chunks(chunk_size=8192),
         headers={"Content-Disposition": f"attachment; filename={object_name}"})
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="S3 credentials not available.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error downloading file from S3: {str(e)}")

@app.get("/downloadfile/", response_class=HTMLResponse)
async def download_file(request: Request, object_name: str = Query(...)):
    return download_from_s3(S3_BUCKET_NAME, object_name)

def decrypt_file(ciphertext_blob, key_id):
    try:
        response = kms_client.decrypt(CiphertextBlob=ciphertext_blob)
        return response['Plaintext']
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="KMS credentials not available.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error decrypting file with KMS: {str(e)}")


def download_and_decrypt_file(bucket_name, object_name):
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=object_name)
        ciphertext_blob = response['Body'].read()

        # Decrypt the file content
        decrypted_content = decrypt_file(ciphertext_blob, KMS_KEY_ID)

        # Get the user's home directory and construct the file path
        home_directory = os.path.expanduser("~")
        download_path = os.path.join(home_directory, "Downloads", object_name)

        # Write the decrypted content to the local file
        with open(download_path, "wb") as local_file:
            local_file.write(decrypted_content)

        return f"File downloaded and stored at: {download_path}"
    except NoCredentialsError:
        raise HTTPException(status_code=500, detail="S3 or KMS credentials not available.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error downloading and decrypting file: {str(e)}")

@app.post("/download_and_decrypt/", response_class=HTMLResponse)
async def download_and_decrypt(request: Request, object_name: str = Form(...)):
    try:
        message = download_and_decrypt_file(S3_BUCKET_NAME, object_name)
        return RedirectResponse(url="/sucess", status_code=303)
    except HTTPException as e:
        return template.TemplateResponse("home.html", {"request": request, "errors": [str(e)]})



