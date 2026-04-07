from fastapi import FastAPI, Depends, HTTPException, WebSocket, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import hashlib, base64
from apscheduler.schedulers.asyncio import AsyncScheduler
from contextlib import asynccontextmanager

# === КОНФИГУРАЦИЯ ===
ENCRYPTION_KEY = hashlib.sha256(b"gramofon_secret_2026").digest()
APP_VERSION = "1.0.0"  # Увеличивай при каждом обновлении!

def encrypt_message(msg: str) -> str:
    enc = bytes([msg.encode('utf-8')[i] ^ ENCRYPTION_KEY[i % len(ENCRYPTION_KEY)] for i in range(len(msg.encode('utf-8')))])
    return base64.b64encode(enc).decode('utf-8')

def decrypt_message(enc: str) -> str:
    dec = bytes([base64.b64decode(enc)[i] ^ ENCRYPTION_KEY[i % len(ENCRYPTION_KEY)] for i in range(len(base64.b64decode(enc)))])
    return dec.decode('utf-8')

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.start()
    yield
    scheduler.shutdown()

app = FastAPI(title="Gramofon Backend", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")

scheduler = AsyncScheduler()
async def cleanup():
    db = SessionLocal()
    try:
        expired = db.query(Message).filter(Message.delete_at <= datetime.utcnow(), Message.is_deleted == False).all()
        for m in expired: m.is_deleted = True; m.content_encrypted = None
        db.commit()
    finally: db.close()
scheduler.add_job(cleanup, 'interval', minutes=1)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

@app.post("/register")
async def register(username: str, password: str, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "User exists")
    db.add(User(username=username, hashed_password=hashlib.sha256(password.encode()).hexdigest()))
    db.commit()
    return {"status": "ok"}

@app.post("/token")
async def login(username: str, password: str, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.username == username, User.hashed_password == hashlib.sha256(password.encode()).hexdigest()).first()
    if not u: raise HTTPException(401, "Invalid")
    return {"access_token": str(u.id), "token_type": "bearer"}

@app.get("/users")
async def get_users(db: Session = Depends(get_db)):
    return [{"id": u.id, "username": u.username} for u in db.query(User).all()]

@app.get("/api/version")
async def get_version():
    return {"version": APP_VERSION, "apk_url": "/static/gramofon.apk"}

active_ws = {}
@app.websocket("/ws/{user_id}")
async def ws_endpoint(websocket: WebSocket, user_id: int, db: Session = Depends(get_db)):
    await websocket.accept()
    active_ws[user_id] = websocket
    try:
        while True:
            raw = await websocket.receive_text()
            parts = raw.split(":", 2)
            if len(parts) != 3: continue
            recv_id, content, _ = int(parts[0]), parts[1], 2  # 🔒 ВСЕГДА 2 МИНУТЫ
            enc = encrypt_message(content)
            msg = Message(sender_id=user_id, receiver_id=recv_id, content_encrypted=enc, delete_at=datetime.utcnow() + timedelta(minutes=2))
            db.add(msg); db.commit()
            if recv_id in active_ws:
                try: await active_ws[recv_id].send_text(f"{user_id}:{msg.id}:{enc}")
                except: pass
    except: pass
    finally: active_ws.pop(user_id, None)

@app.get("/")
async def root(): return {"app": "Gramofon", "version": APP_VERSION}
