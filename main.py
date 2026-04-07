from fastapi import FastAPI, Depends, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import hashlib, base64
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

# === ENCRYPTION ===
ENCRYPTION_KEY = hashlib.sha256(b"gramofon_secret_2026").digest()
APP_VERSION = "1.0.1"

def encrypt_message(msg: str) -> str:
    enc = bytes([msg.encode("utf-8")[i] ^ ENCRYPTION_KEY[i % len(ENCRYPTION_KEY)] for i in range(len(msg.encode("utf-8")))])
    return base64.b64encode(enc).decode("utf-8")

def decrypt_message(enc: str) -> str:
    dec = bytes([base64.b64decode(enc)[i] ^ ENCRYPTION_KEY[i % len(ENCRYPTION_KEY)] for i in range(len(base64.b64decode(enc)))])
    return dec.decode("utf-8")

# === DATABASE ===
SQLALCHEMY_DATABASE_URL = "sqlite:///./gramofon.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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
    content_encrypted = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    delete_at = Column(DateTime, nullable=True)
    is_deleted = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# === APP ===
app = FastAPI(title="Gramofon Backend")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# === SCHEDULER (FIXED) ===
scheduler = BackgroundScheduler()
scheduler.start()

def cleanup_expired_messages():
    db = SessionLocal()
    try:
        expired = db.query(Message).filter(Message.delete_at <= datetime.utcnow(), Message.is_deleted == False).all()
        for msg in expired:
            msg.is_deleted = True
            msg.content_encrypted = None
        db.commit()
        print(f"🗑️ Deleted {len(expired)} messages")
    finally:
        db.close()

# Run cleanup every 5 minutes
scheduler.add_job(cleanup_expired_messages, "interval", minutes=5)

# Shutdown scheduler on exit
atexit.register(lambda: scheduler.shutdown())

# === HELPERS ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# === ROUTES ===
@app.post("/register")
async def register(username: str, password: str, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(400, "User exists")
    new_user = User(username=username, hashed_password=hash_password(password))
    db.add(new_user)
    db.commit()
    return {"status": "ok"}

@app.post("/token")
async def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username, User.hashed_password == hash_password(password)).first()
    if not user:
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": str(user.id), "token_type": "bearer"}

@app.get("/users")
async def get_users(db: Session = Depends(get_db)):
    return [{"id": u.id, "username": u.username} for u in db.query(User).all()]

@app.get("/api/version")
async def get_version():
    return {"version": APP_VERSION, "apk_url": "/static/gramofon.apk"}

@app.get("/messages/{sender}/{receiver}")
async def get_messages(sender: int, receiver: int, db: Session = Depends(get_db)):
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
            "delete_at": msg.delete_at.isoformat() if msg.delete_at else None
        })
    return result

# === WEBSOCKET ===
active_connections = {}

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    await websocket.accept()
    active_connections[user_id] = websocket
    try:
        while True:
            data = await websocket.receive_text()
            parts = data.split(":", 2)
            if len(parts) != 3:
                continue
            receiver_id = int(parts[0])
            content = parts[1]
            delete_minutes = 2  # ALWAYS 2 MINUTES
            
            encrypted = encrypt_message(content)
            msg = Message(
                sender_id=user_id,
                receiver_id=receiver_id,
                content_encrypted=encrypted,
                delete_at=datetime.utcnow() + timedelta(minutes=delete_minutes)
            )
            db.add(msg)
            db.commit()
            
            if receiver_id in active_connections:
                try:
                    await active_connections[receiver_id].send_text(f"{user_id}:{msg.id}:{encrypted}")
                except:
                    pass
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        active_connections.pop(user_id, None)

@app.get("/")
async def root():
    return {"app": "Gramofon", "version": APP_VERSION, "status": "running"}
