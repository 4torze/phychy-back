from typing import List
from fastapi import FastAPI, Depends, HTTPException
from shemas import UserAccountCreate, UserAccountResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import uuid
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from fastapi.middleware.cors import CORSMiddleware
import os

DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    first_connection = Column(Boolean, default=True)
    is_logged_in = Column(Boolean, default=False)
    token_jti = Column(String, nullable=True)
    first_login_date = Column(DateTime, nullable=True)
    token_validity_days = Column(Integer, default=ACCESS_TOKEN_EXPIRE_DAYS)

    user_accounts = relationship("UserAccount", back_populates="account", cascade="all, delete-orphan")






class UserAccount(Base):
    __tablename__ = "user_accounts"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=False, index=True, nullable=False)
    password = Column(String, nullable=False)
    platform = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    account_id = Column(Integer, ForeignKey("accounts.id"))

    account = relationship("Account", back_populates="user_accounts")


Base.metadata.create_all(bind=engine)

app = FastAPI()


# Configuration CORS pour accepter toutes les origines
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ✅ Autorise toutes les origines
    allow_credentials=True,
    allow_methods=["*"],  # ✅ Autorise toutes les méthodes (GET, POST, etc.)
    allow_headers=["*"],  # ✅ Autorise tous les headers
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/register/")
def register(username: str, password: str, token_validity_days: int, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(password)
    user = Account(username=username, password=hashed_password, token_validity_days=token_validity_days)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User created","user_id":user.id}

@app.post("/login/")
def login(user_client: dict, db: Session = Depends(get_db)):
    username = user_client.get("username")
    password = user_client.get("password")
    user = db.query(Account).filter(Account.username == username).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    # if user.is_logged_in:
    #     raise HTTPException(status_code=400, detail="User already logged in")
    
    jti = str(uuid.uuid4())
    access_token = create_access_token(
        {"sub": user.username, "jti": jti}, 
        timedelta(days=user.token_validity_days)
    )
    user.is_logged_in = True
    user.token_jti = jti
    if user.first_connection:
        user.first_login_date = datetime.utcnow()
        user.first_connection = False
    db.commit()
    user = db.query(Account).filter(Account.username == username).first()  # Requête SQL après commit

    return {"access_token": access_token, "token_type": "bearer","user":user}

@app.post("/logout/")
def logout(username: str, db: Session = Depends(get_db)):
    user = db.query(Account).filter(Account.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    user.is_logged_in = False
    user.token_jti = None
    db.commit()
    return {"message": "User logged out"}

@app.post("/check_account/")
def check_account(username: str, db: Session = Depends(get_db)):
    user = db.query(Account).filter(Account.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    if user.first_connection and user.first_login_date is None:
        raise HTTPException(status_code=400, detail="Account not activated yet.")
    
    if user.first_connection == False and datetime.utcnow() > user.first_login_date + timedelta(days=user.token_validity_days):
        user.is_logged_in = False
        db.commit()
        raise HTTPException(status_code=400, detail="Account no longer valid due to token expiration.")

    return {"message": "Account is still valid" ,"active":True}

# 1️⃣ Ajouter un UserAccount
@app.post("/user_accounts/", response_model=UserAccountResponse)
def create_user_account(user_data: UserAccountCreate, db: Session = Depends(get_db)):
    # Vérifier si le compte existe
    account = db.query(Account).filter(Account.id == user_data.account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # Créer un nouvel UserAccount
    new_user_account = UserAccount(
        email=user_data.email,
        password=user_data.password,
        platform=user_data.platform,
        account_id=user_data.account_id
    )
    db.add(new_user_account)
    db.commit()
    db.refresh(new_user_account)
    
    return new_user_account

# 2️⃣ Récupérer les UserAccount d'un Account spécifique
# Si vous n'avez pas déjà un modèle Pydantic pour la requête
class UserAccountRequest(BaseModel):
    account_id: int

@app.post("/user_accounts", response_model=List[UserAccountResponse])
def get_user_accounts(request: UserAccountRequest, db: Session = Depends(get_db)):
    user_accounts = db.query(UserAccount).filter(UserAccount.account_id == request.account_id).all()
    
    if not user_accounts:
        raise HTTPException(status_code=404, detail="No user accounts found for this account")
    
    return user_accounts

class EmailRequest(BaseModel):
    receiver_email: EmailStr
    subject: str
    message_body: str

SMTP_SERVER = "smtp.example.com"  # Change with your SMTP server (e.g., Gmail)
SMTP_PORT = 587
SENDER_EMAIL = "your_email@example.com"  # Change with your sender email
SENDER_PASSWORD = "your_email_password"  # Change with your email password

@app.post("/send_email/")
async def send_email(email_request: EmailRequest):
    try:
        # Validate receiver email
        validate_email(email_request.receiver_email)

        # Create the email
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = email_request.receiver_email
        msg['Subject'] = email_request.subject
        msg.attach(MIMEText(email_request.message_body, 'plain'))

        # Connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure connection
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, email_request.receiver_email, msg.as_string())

        return {"message": "Email sent successfully!"}

    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=f"Invalid email address: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error sending email: {str(e)}")




if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8000)))
