#!/usr/bin/python3
from sqlalchemy import Column, ForeignKey, Integer, String, TIMESTAMP, func, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import random, string

from sqlalchemy import create_engine
import time, datetime

Base = declarative_base()

class Users(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    fname = Column(String(32), nullable=False)
    lname = Column(String(32), nullable=False)
    username = Column(String(32), index=True, nullable=False, unique=True)
    email = Column(String(256), index=True, nullable=False, unique=True)
    password = Column(String(64), index=False, nullable=False)
    create_time = Column(TIMESTAMP, server_default=func.now())
    active = Column(String(1), default='N')
    act_link = Column(String(64), default=''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for x in range(64)))


class Chat(Base):
    __tablename__ = 'chat'
    id = Column(Integer, primary_key=True)
    from_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    sender = relationship(Users, foreign_keys=[from_id])
    to_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    reveiver = relationship(Users, foreign_keys=[to_id])
    create_time = Column(TIMESTAMP, server_default=func.now())


class Messages(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey('chat.id'))
    create_time = Column(TIMESTAMP, server_default=func.now())
    sender_id = Column(Integer, ForeignKey('users.id'))
    msg_body = Column(String(1024), index=False)
    users = relationship(Users)
    chat = relationship(Chat)

class Reset(Base):
    __tablename__ = 'reset'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    hash_link = Column(String(64), unique=True)
    link_time = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    users = relationship(Users, foreign_keys=[user_id])

class Lock(Base):
    __tablename__ = 'locked'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    f_time = Column(TIMESTAMP, server_default=func.now())
    count = Column(Integer)
    users = relationship(Users)

