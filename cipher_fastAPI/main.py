"""
Python FastAPI server for sending encrypted messages between users. Encryption is based on RSA algorithm.
"""


from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, status
import models
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from pydantic import BaseModel
from models import User, Message
from sqlalchemy.exc import IntegrityError
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

app = FastAPI()
security = HTTPBasic()
models.Base.metadata.create_all(bind=engine)
db = []


def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, "exploIF")
    correct_password = secrets.compare_digest(credentials.password, "synapsi.xyz")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


class UserRequest(BaseModel):
    username: str


class MessageRequest(BaseModel):
    sender: str
    receiver: str
    text: str


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def fetch_user_data(username: str):
    """
    Function witch automatically initialize user's key after creating new user.

    Parameters
    -------
    username: str
        Recently created user's name
    """

    db = SessionLocal()
    current_user = db.query(User).filter(User.username == username).first()
    current_user.public_key_e, current_user.public_key_n, current_user.private_key_d = current_user.key_generator()
    db.commit()


@app.post('/user/create',  dependencies=[Depends(get_current_username)])
async def create_user(user_request: UserRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Endpoint for creating users
    """

    try:
        new_user = User(username=user_request.username)
        db.add(new_user)
    except IntegrityError:
        return {"code": "user with this username already exists"}
    else:
        db.commit()
        background_tasks.add_task(fetch_user_data, new_user.username)
        return {"code": "success"}


@app.get('/user/', dependencies=[Depends(get_current_username)])
async def all_users(db: Session = Depends(get_db)):
    """
    Endpoint for seeing all users, their names and public keys.
    """

    all_users = db.query(User).all()
    users = {}
    for user in all_users:
        users[user.username] = user.public_key_n, user.public_key_e
    return users


@app.get('/user/{username}', dependencies=[Depends(get_current_username)])
async def user(username: str, db: Session = Depends(get_db)):
    """
    Endpoint for seeing all information about single user.

    Parameters
    _______
    username: str
        User's name.
    """

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404)
    else:
        return {'username': user.username,
                'public_key': (user.public_key_e, user.public_key_n),
                'private_key': user.private_key_d}


@app.delete('/user/delete/{username}', dependencies=[Depends(get_current_username)])
async def delete_user(username: str, db: Session = Depends(get_db)):
    """
    Endpoint for deleting user.

    Parameters
    _______
    username: str
        User's name.
    """

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404)
    else:
        db.delete(user)
        db.commit()
        return{'code': 'user_deleted'}


@app.post('/message/write', dependencies=[Depends(get_current_username)])
async def write_message(message_request: MessageRequest, db: Session = Depends(get_db)):
    """
    Endpoint for writing and sending messages.

    Parameters
    ________
    sender_username: str
        Sender's name.
    receiver_username: str
        Receiver's name.
    message: str
        Message text.
    """

    if (db.query(User).filter_by(username=message_request.receiver).first() and
        db.query(User).filter_by(username=message_request.sender).first()):
            new_message = Message(sender=message_request.sender, receiver=message_request.receiver)
            db.add(new_message)
            new_message.coded_message = new_message.encryption(message_request.text)
            db.add(new_message)
    else:
        raise HTTPException(status_code=404, detail='sender or receiver not found')
    db.commit()
    return {"code": "success"}


@app.get('/message/show/{username}', dependencies=[Depends(get_current_username)])
async def show_messages(username: str, db: Session = Depends(get_db)):
    """
    Endpoint for showing user's messages.

    Parameters
    ________
    username: str
        User's name.
    """

    messages_dict = {}
    messages = db.query(Message).filter(Message.receiver == username).all()
    if not user or not messages:
        raise HTTPException(status_code=404, detail='user not found')
    else:
        for message in messages:
            messages_dict[message.message_id] = {'sender': message.sender,
                                                  'receiver': message.receiver,
                                                  'date': message.date_time,
                                                  'coded_text': message.coded_message,
                                                  'encoded_text': message.decryption()}
    return messages_dict


@app.get('/message/read/{message_id}', dependencies=[Depends(get_current_username)])
async def read_message(message_id: int, db: Session = Depends(get_db)):
    """
    Endpoint for showing information about message.

    Parameters
    ________
    message_id: int
        Id of message.
    """

    message = db.query(Message).filter(Message.message_id == message_id).first()
    if not message:
        raise HTTPException(status_code=404)
    else:
        return {'sender': message.sender,
                'receiver': message.receiver,
                'date': message.date_time,
                'coded_text': message.coded_message,
                'encoded_text': message.decryption()}


@app.delete('/message/delete/{message_id}', dependencies=[Depends(get_current_username)])
async def delete_message(message_id: int, db: Session = Depends(get_db)):
    """
    Endpoint for deleting message.

    Parameters
    ________
    message_id: int
        Id of message.
    """

    message = db.query(Message).filter(Message.message_id == message_id).first()
    if not message:
        raise HTTPException(status_code=404)
    else:
        db.delete(message)
        db.commit()
        return {'code': 'message deleted'}

