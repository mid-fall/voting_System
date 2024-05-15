import datetime
import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///data.db', echo=True)
Base = declarative_base()   # SQLAlchemy基类
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)


class Vote(Base):
    __tablename__ = 'votes'
    id = Column(Integer, primary_key=True)
    VoteName = Column(String, nullable=False)
    VoteDes = Column(String, nullable=True)
    DeadLine = Column(DateTime, nullable=False)


users = session.query(User).all()
for user in users:
    print(f"ID: {user.id}, Username: {user.username}, Password: {user.password}")


# Base.metadata.create_all(engine)
#
# new_vote = Vote(VoteName='最喜欢的老师', VoteDes='Please vote for your favorite teacher', DeadLine=datetime.datetime(2024,4,15,12,0,0))
# session.add(new_vote)
# session.commit()