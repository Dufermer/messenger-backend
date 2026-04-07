from fastapi import FastAPI, Depends, HTTPException, WebSocket, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from datetime import datetime, timedelta
from typing import Optional
import hashlib
import base64
from apscheduler.schedulers.asyncio import AsyncScheduler
from contextlib import asynccontextmanager

# === ENCRYPTION ===
ENCRYPTION_KEY = hashlib.sha256(b"messenger_secret_key_2026").digest()  # В продакшене - из env!

def encrypt_message(message: str) -> str:
    """Простое XOR шифрование (для MVP)"""
    key_bytes = ENCRYPTION_KEY
    message_bytes = message.encode('utf-8')
    encrypted = bytes([message_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(message_bytes))])
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted: str) -> str:
    """Расшифровка"""
    key_bytes = ENCRYPTION_KEY
    encrypted_bytes = base64.b64decode(encrypted.encode('utf-8'))
    decrypted = bytes([encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encrypted_bytes))])
    return decrypted.decode('utf-8')

# === DATABASE ===
SQLALCHEMY_DATABASE_URL = "sqlite:///./messenger.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === MODELS ===
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    content_encrypted = Column(String)  # Зашифрованный контент
    timestamp = Column(DateTime, default=datetime.utcnow)
    delete_at = Column(DateTime, nullable=True)  # Когда удалить
    read_at = Column(DateTime, nullable=True)    # Когда прочитано
    is_deleted = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# === LIFESPAN ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Запуск планировщика при старте
    scheduler.start()
    yield
    # Остановка при завершении
    scheduler.shutdown()

app = FastAPI(title="Secure Messenger", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === SCHEDULER ===
scheduler = AsyncScheduler()

async def cleanup_expired_messages():
    """Удаляет истекшие сообщения"""
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        expired = db.query(Message).filter(
            Message.delete_at <= now,
            Message.is_deleted == False
        ).all()
        
        for msg in expired:
            msg.is_deleted = True
            # Опционально: удаляем контент
            msg.content_encrypted = None
        
        db.commit()
        print(f"🗑️ Удалено {len(expired)} сообщений")
    finally:
        db.close()

# Запускаем проверку каждые 5 минут
scheduler.add_job(cleanup_expired_messages, 'interval', minutes=5)

# === DEPENDENCIES ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or user.hashed_password != hash_password(password):
        return None
    return user

# === ROUTES ===
@app.post("/register")
async def register(username: str, password: str, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="User exists")
    
    new_user = User(username=username, hashed_password=hash_password(password))
    db.add(new_user)
    db.commit()
    return {"message": "Created", "username": username}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": str(user.id), "token_type": "bearer"}

@app.get("/users")
async def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username} for u in users]

@app.get("/messages/{sender}/{receiver}")
async def get_messages(sender: int, receiver: int, db: Session = Depends(get_db)):
    """Получить историю сообщений (расшифрованную)"""
    messages = db.query(Message).filter(
        ((Message.sender_id == sender) & (Message.receiver_id == receiver)) |
        ((Message.sender_id == receiver) & (Message.receiver_id == sender))
    ).filter(Message.is_deleted == False).order_by(Message.timestamp).all()
    
    result = []
    for msg in messages:
        decrypted = decrypt_message(msg.content_encrypted) if msg.content_encrypted else "[DELETED]"
        result.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "content": decrypted,
            "timestamp": msg.timestamp.isoformat(),
            "delete_at": msg.delete_at.isoformat() if msg.delete_at else None,
            "is_deleted": msg.is_deleted
        })
    return result

@app.post("/messages/{user_id}/read")
async def mark_as_read(message_id: int, user_id: int, db: Session = Depends(get_db)):
    """Отметить как прочитанное и запустить таймер удаления"""
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Not found")
    
    if not msg.read_at:  # Первый раз открыли
        msg.read_at = datetime.utcnow()
        # Таймер 5 минут по умолчанию
        msg.delete_at = msg.read_at + timedelta(minutes=5)
        db.commit()
    
    return {"status": "ok", "delete_at": msg.delete_at.isoformat()}

# === WEBSOCKET ===
active_connections: dict = {}

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    await websocket.accept()
    active_connections[user_id] = websocket
    
    try:
        while True:
            data = await websocket.receive_text()
            # Формат: "receiver_id:content:delete_minutes"
            parts = data.split(":", 2)
            if len(parts) != 3:
                continue
            
            receiver_id = int(parts[0])
            content = parts[1]
            delete_minutes = int(parts[2]) if parts[2] else 5  # 5 мин по умолчанию
            
            # Шифруем
            encrypted = encrypt_message(content)
            
            # Сохраняем
            msg = Message(
                sender_id=user_id,
                receiver_id=receiver_id,
                content_encrypted=encrypted,
                delete_at=datetime.utcnow() + timedelta(minutes=delete_minutes) if delete_minutes > 0 else None
            )
            db.add(msg)
            db.commit()
            
            # Отправляем получателю
            if receiver_id in active_connections:
                try:
                    await active_connections[receiver_id].send_text(
                        f"{user_id}:{msg.id}:{encrypted}:{delete_minutes}"
                    )
                except:
                    pass
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        active_connections.pop(user_id, None)

@app.get("/")
async def root():
    return {"message": "Secure Messenger API", "docs": "/docs"}
