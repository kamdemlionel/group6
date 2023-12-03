# @app.post("/signup")
# def create_user( user: schemas.UserCreate, db: Session = Depends(get_db)):
#     db_username = crud.get_user_by_name(db, username=user.Username)
#     db_user = crud.get_user_by_email(db, email=user.email)

#     if db_user:
#         raise HTTPException(status_code=400, detail="Email already registered")

#     elif db_username:
#         raise HTTPException(status_code=400, detail="Username already in use")

#     try:
#         return crud.create_user(db=db, user=user)
#     except Exception as e:
#         return JSONResponse(content={"error": str(e)}, status_code=500)


# @app.post('/register')
# async def register(request:Request, db:Session = Depends(get_db)):
#     form= await request.form()
#     Username: str=form.get('text')
#     email:str =form.get('email')
#     password:str =form.get('password')

#     errors=[]
#     # if len(password) < 6:
#     #     errors.append('password must be atleast 6 characters')
#     #     return template.TemplateResponse("register.html", {"request":request, "errors":errors})
#     new_user=models.User( Username=Username, email=email , hashed_password=password)
#     try:
#         db.add(new_user)
#         db.commit()
#         db.refresh(new_user)
#         return responses.RedirectResponse('/?=msg=succesfully registered', status_code=status.HTTP_302_FOUND)
    
#     except IntegrityError:
#         errors.append("user already exist")


# @app.post("/register/")
# async def register(request: Request, db: Session = Depends(get_db)):
#     form = usercreateform(request)
#     await form.load_data()
#     if await form.is_valid():
#         user = UserCreate(
#             username=form.username, email=form.email, password=form.password
#         )
#         try:
#             user = UserCreate(user=user, db=db)
#             return responses.RedirectResponse(
#                 "/?msg=Successfully-Registered", status_code=status.HTTP_302_FOUND
#             )  # default is post request, to use get request added status code 302
#         except IntegrityError:
#             form.__dict__.get("errors").append("Duplicate username or email")
#             return template.TemplateResponse("register.html", form.__dict__)
#     return template.TemplateResponse("register.html", form.__dict__)


# def create_access_token(email:str,user_id:int, expires_delta: timedelta):
#     to_encode={'sub':email, 'id':user_id}
#     expire = datetime.utcnow() + expires_delta
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt


 #async def get_current_user(token:Annotated[str,Depends(oauth2_scheme)]):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         user_id:int=payload.get('id')        
#         if username is None:
#             raise credentials_exception
        
#         return{'username':username, 'id':user_id}
#     except JWTError:
#        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='could not validate user')


# @app.post("/token")
# async def login_for_access_token(form_data:Annotated[OAuth2PasswordRequestForm,Depends()], db: Session = Depends(get_db)):
#     user=authenticate_user(form_data.username, form_data.password, db)

#     if not user:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='could not validate user')
#     token=create_access_token(user.email, user.id, timedelta(minutes=20))  
#     return{
#         'access_token':token, 'token_type':'bearer'
#     } 

# def authenticate_user(username:str, password:str, db: Session = Depends(get_db)):
#     user=db.query(models.User).filter(models.User.email==username, models.User.hashed_password==password).first()

#     if not user:
#         return False
#     return user

# @app.post("/token", response_model=Token)
# def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),db: Session= Depends(get_db)):
#     user = authenticate_user(form_data.username, form_data.password,db)
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#         )
#     access_token = create_access_token(
#         data={"sub": user.email}, expires_delta=access_token_expires
#     )
#     return {"access_token": access_token, "token_type": "bearer"}

# @app.post("/token")
# async def login_for_access_token(form_data: schemas.UserCreate, db: Session = Depends(get_db)):
#     user_db = crud.get_user_by_email(db, email=form_data.email)

#     if user_db and pwd_context.verify(form_data.password, user_db.hashed_password):
#         access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#         access_token = create_access_token(
#             data={"sub": user_db.email}, expires_delta=access_token_expires
#         )
#         return {"access_token": access_token, "token_type": "bearer"}

#     raise HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Invalid credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )

# def encrypt_file(file_content, key_id):
#     try:
#         response = kms_client.encrypt(KeyId=key_id, Plaintext=file_content)
#         return response['CiphertextBlob']
#     except NoCredentialsError:
#         raise HTTPException(status_code=500, detail="KMS credentials not available.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error encrypting file with KMS: {str(e)}")

# def encrypt_and_upload_file(file_path, key_id):
#     with open(file_path, 'rb') as file:
#         content = file.read()
#         encrypted_content = encrypt_file(content, key_id)
        
#         # Upload the encrypted content to S3
#         s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=os.path.basename(file_path), Body=encrypted_content)

# def encrypt_and_upload_folder(folder_path, key_id):
#     for root, dirs, files in os.walk(folder_path):
#         for file in files:
#             file_path = os.path.join(root, file)
#             encrypt_and_upload_file(file_path, key_id)

# @app.post("/encryptfile/")
# async def create_encrypt_file(file: UploadFile = File(...)):
#     try:
#         # Create a temporary directory to store the uploaded files
#         temp_dir = '/tmp/uploaded_files'
#         os.makedirs(temp_dir, exist_ok=True)

#         # Save the uploaded file to the temporary directory
#         file_path = os.path.join(temp_dir, file.filename)
#         with open(file_path, 'wb') as f:
#             f.write(await file.read())

#         # Check if the uploaded file is a folder or a file
#         if os.path.isdir(file_path):
#             encrypt_and_upload_folder(file_path, KMS_KEY_ID)
#         else:
#             encrypt_and_upload_file(file_path, KMS_KEY_ID)

#         return {"message": "Files encrypted and stored in S3"}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")
#     finally:
#         # Remove the temporary directory and its contents
#         shutil.rmtree(temp_dir, ignore_errors=True)
# @app.get("/home", response_class=HTMLResponse)
# async def render_form(request: Request):
#     return template.TemplateResponse("home.html", {"request": request})

# @app.get("/download_and_decrypt")
# async def download_and_decrypt(request: Request, object_name: str = Form(...)):
#     try:
#         # Call your existing function passing the object_name
#         result = download_and_decrypt_file(S3_BUCKET_NAME, object_name)
#         return {"file succesfully downloaded": result["message"]}
#     except HTTPException as e:
#         return e

# def download_from_s3(bucket_name, object_name):
#     try:
#         response = s3_client.get_object(Bucket=bucket_name, Key=object_name)
#         ciphertext_blob = response['Body'].read()

#         # Decrypt the file content
#         decrypted_content = decrypt_file(ciphertext_blob, KMS_KEY_ID)

#         return StreamingResponse(content=decrypted_content,
#                                  headers={"Content-Disposition": f"attachment; filename={object_name}"})
#     except NoCredentialsError:
#         raise HTTPException(status_code=500, detail="S3 credentials not available.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error downloading file from S3: {str(e)}")

# @app.get("/downloadfile and decrypt/{object_name}")
# async def download_file(object_name: str):
#     return download_from_s3(S3_BUCKET_NAME, object_name)

# def encrypt_file(file_content, key_id):
#     try:
#         response = kms_client.encrypt(KeyId=key_id, Plaintext=file_content)
#         return response['CiphertextBlob']
#     except NoCredentialsError:
#         raise HTTPException(status_code=500, detail="KMS credentials not available.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error encrypting file with KMS: {str(e)}")

# @app.post("/encryptfile/")
# async def create_encrypt_file(file: UploadFile = File(...)):
#     try:
#         content = await file.read()
#         encrypted_content = encrypt_file(content, KMS_KEY_ID)
#         return {"encrypted_content": encrypted_content.decode('utf-8')}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

