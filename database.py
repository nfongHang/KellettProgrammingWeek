import sqlalchemy as sa
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base
import os


db_url='sqlite:///main.db' # path to database

engine = sa.create_engine(db_url) # connect to server

base = declarative_base()

class User(base):
    __tablename__ = "users"

    uid = Column(Integer, primary_key=True)
    house = Column(String)
    class_id = Column(Integer)
    user_email = Column(String)
    username = Column(String)
    pwd_hash = Column(String)
    user_score = Column(Integer)

class Questions(base):
    __tablename__ = "questions"

    question_id = Column(Integer, primary_key=True)
    question_desc = Column(Integer)

class QuestionsToInputs(base):
    __tablename__ = "questions_to_inputs"
    
    question_id = Column(Integer, primary_key=True)
    inputset_id = Column(Integer, primary_key=True)
    inputset_data = Column(String)
    inputset_answer = Column(String)

class UserSolutions(base):
    __tablename__ = "user_solutions"

    uid = Column(Integer,primary_key=True)
    inputset_id = Column(Integer,primary_key=True)
    complete = Column(Boolean)

class Class(base):
    __tablename__ = "class"

    class_id = Column(Integer,primary_key=True)
    class_score = Column(Integer)

class House(base):
    __tablename__ = "house"
    
    house = Column(String,primary_key=True)
    house_score = Column(Integer)
    
base.metadata.create_all(engine)