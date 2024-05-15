#TODO: Authorization for some request
import datetime
import json
import random

import requests
import yaml
from flask import request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, MetaData, Column, Integer, String, DateTime
from src.bingovoting.machines import PedersenBVM
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import flask
from flask_cors import CORS
import logging
from ..cryptography.cryptofunction import Generator
from ..bingovoting.function import *

server = flask.Flask(__name__)
CORS(server)

server.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'

Base = declarative_base()  # SQLAlchemy基类
db = create_engine('sqlite:///data.db', echo=True)
Session_db = sessionmaker(bind=db)
session_db = Session_db()
# 禁用SQLALchemy的warning日志输出
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

OK = 200
ACCEPTED = 202
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
NOT_ACCEPTABLE = 406

USERCERT_ISSUED = 0
USERCERT_REJECT = 1

ADMINISTRATOR_PASS = 0
ADMINISTRATOR_REJECT = 1

try:
    with open('src/server/config.yml', 'r') as stream:
        config = yaml.safe_load(stream)
except FileNotFoundError:
    server.logger.error('[server.py] Config file not found')
    exit()

bvm_machine = PedersenBVM(config['bvm'])

select_vote_id = None

class UserSecret(Base):
    __tablename__ = 'UserSecret'
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    public_key = Column(String, nullable=False)


class UserInfo(Base):
    __tablename__ = 'UserInfo'
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    e_mail = Column(String, nullable=False)
    sex = Column(String, nullable=False)


class CollectPoll(Base):
    __tablename__ = 'CollectPoll'
    vote_id = Column(Integer, primary_key=True)
    vote_owner = Column(Integer, nullable=False)    # VCC的身份标识
    vote_name = Column(String, nullable=False)
    vote_des = Column(String, nullable=True)
    vote_ddl = Column(DateTime, nullable=False)
    vote_op1 = Column(String, nullable=True)  # 必须有一个选项
    vote_op2 = Column(String, nullable=False)
    vote_op3 = Column(String, nullable=False)
    vote_op4 = Column(String, nullable=False)


class TempPoll(Base):
    __tablename__ = 'TempPoll'
    vote_id = Column(Integer, primary_key=True)
    vote_owner = Column(Integer, nullable=False)    # 投票发起人的身份标识
    vote_title = Column(String, nullable=False)
    vote_description = Column(String, nullable=True)
    vote_deadline = Column(DateTime, nullable=False)
    vote_options_1 = Column(String, nullable=True)  # 必须有一个选项
    vote_options_2 = Column(String, nullable=False)
    vote_options_3 = Column(String, nullable=False)
    vote_options_4 = Column(String, nullable=False)

class PollResult(Base):
    __tablename__ = 'PollResult'
    record_id = Column(Integer, primary_key=True)
    poll_id = Column(Integer, nullable=False)
    op1_num = Column(Integer)
    op2_num = Column(Integer)
    op3_num = Column(Integer)
    op4_num = Column(Integer)
    invalid_num = Column(Integer)
    total_num = Column(Integer)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class PollCertPK(Base):
    __tablename__ = 'PollCertPK'
    record_id = Column(Integer, primary_key=True)
    vote_id = Column(Integer, nullable=False)   # 证书对应的投票编号，值应为CollectPoll中的vote_id值
    cert_id = Column(Integer, nullable=False)   # 证书编号
    cert_pk = Column(String, nullable=False)    # 证书中的公钥，记录

class PollUserWithCert(Base):
    __tablename__ = 'PollUserWithCert'
    record_id = Column(Integer, primary_key=True)
    vote_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=False)   # 投票中已分配证书的用户编号，拒绝给他们分配证书


class UserVotes(Base):
    __tablename__ = 'UserVotes'
    vote_record_id = Column(Integer, primary_key=True)
    vote_id = Column(Integer, nullable=False)               # 某项投票的编号
    cert_id = Column(Integer, nullable=False)               # 投票有效编号
    encrypt_vote_data = Column(String, nullable=False)      # 用户投票加密数据
    encrypt_vote_content = Column(String, nullable=False)   # 未解密的投票内容
    TimeStamp = Column(Integer, nullable=False)            # 投票时间戳，整形


# 利用反射功能获取数据库中已有的表信息
metadata = MetaData()
metadata.reflect(bind=db)

Base.metadata.create_all(db)


@server.route('/')
def start():
    return 'It works!'  # 后续重定向到index路由


@server.route('/index')
def index():
    return flask.render_template('server_index.html')


@server.route('/login/cert', methods=['GET', 'POST'])
def login_cert():
    if request.method == "GET":  # 初始情况下直接加载模板
        return flask.render_template('login_cert.html')
    elif request.method == "POST":
        input_username = request.form.get('username')
        input_password = request.form.get('password')

        # 写死了，记得修改
        protocol = 'http'
        client_ip = request.remote_addr
        client_port = '9003'
        client_file_path = '/vote_option'

        users = session_db.query(UserSecret).all()
        for user in users:
            if input_username == user.username:
                if input_password == user.password:
                    print('BBBBBBBBB')
                    user_id = user.id
                    vote_id = select_vote_id
                    if vote_id == None:
                        print('Error input vote_id: None')
                        return '0'

                    remote_url = '{}://{}:{}{}'.format(protocol, client_ip, client_port, client_file_path)
                    gen_cert(user_id)

                    return flask.render_template('login_success.html', remote_url=remote_url)
        message = '登录失败，请检查用户名和密码'
        return flask.render_template('login_cert.html', message=message)


@server.route('/login/vcc', methods=['GET', 'POST'])
def login_vcc():
    if request.method == "GET":  # 初始情况下直接加载模板
        return flask.render_template('login_vcc.html')
    elif request.method == "POST":
        input_username = request.form.get('username')
        input_password = request.form.get('password')

        # 写死了，记得修改
        protocol = 'http'
        client_ip = request.remote_addr
        client_port = '9002'
        client_file_path = '/rec_cert'

        users = session_db.query(UserSecret).all()
        for user in users:
            if input_username == user.username:
                if input_password == user.password:
                    remote_url = '{}://{}:{}{}'.format(protocol, client_ip, client_port, client_file_path)
                    # return redirect(generate_cert)
                    gen_cert()
                    return flask.render_template('login_success.html', remote_url=remote_url)
        message = '登录失败，请检查用户名和密码'
        return flask.render_template('login_vcc.html', message=message)


@server.route('/rec_user_vote_id', methods=['POST'])
def rec_user_vote_id():
    data = request.get_json()
    user_vote_id = data.get('vote_id')
    global select_vote_id
    select_vote_id = int(user_vote_id)
    print(select_vote_id)
    print(type(select_vote_id))
    return '0'

@server.route('/submit_data', methods=['POST'])
def submit_data():
    data = request.json  # 获取客户端发送过来的JSON数据
    print(data)
    # 对数据进行处理，例如保存到数据库等操作

    return jsonify(status='success', message='Data received and processed successfully!')


def gen_cert(user_id):
    vote_id = select_vote_id
    existing_user = session_db.query(PollUserWithCert).filter_by(vote_id=vote_id, user_id=user_id).first()
    print('AAAAAAAAAAAA')
    if existing_user:
    # if 1 == 0:
        print('Reject to assign cert to user', user_id,', for he has a cert already')
        generated_cert = None
        client_url = 'http://127.0.0.1:9003/rec_cert'
        cert_response = requests.post(client_url, json=generated_cert)
        return USERCERT_REJECT
    else:
        new_poll_userwithcert = PollUserWithCert(vote_id=vote_id, user_id=user_id)
        generator_instance = Generator()
        generated_cert = generator_instance.generate_secret_keys()
        while True:
            new_cert_id = random.randint(1, 10000)      # 生成不重复的证书编号
            existing_cert = session_db.query(PollCertPK).filter_by(cert_id=new_cert_id, vote_id=vote_id).first()
            if not existing_cert:
                break

        new_poll_cert_pk = PollCertPK(
            vote_id=vote_id,
            cert_id=new_cert_id,
            cert_pk=generated_cert['pk']
        )
        print('cert:', generated_cert)
        client_url = 'http://127.0.0.1:9003/rec_cert'
        cert = (new_cert_id, generated_cert)
        # cert = {'cert_id': new_cert_id, 'cert_content': generated_cert}
        cert_response = requests.post(client_url, json=cert)

        if cert_response.status_code == 200:
            print('Cert Sent successfully!')
            session_db.add(new_poll_userwithcert)
            session_db.add(new_poll_cert_pk)
            session_db.commit()

        return USERCERT_ISSUED


@server.route('/request_for_info', methods=['POST'])
def request_for_info():
    request_data = request.get_json()
    request_type = request_data.get('request_type')
    if request_type == 'cert_pk':
        cert_id = request_data.get('cert_id')
        cert = session_db.query(PollCertPK).filter_by(cert_id=cert_id).first()
        if cert:
            vote_id = cert.vote_id
            cert_pk = cert.cert_pk
            result = (cert_pk, vote_id)
            return jsonify(result)
        else:
            return jsonify(None)
    elif request_type == 'poll_info':
        poll_id = request_data.get('poll_id')
        poll_info = session_db.query(CollectPoll).filter_by(vote_id=poll_id).first()
        if poll_info:
            TimeStamp = DateTime2Int(poll_info.vote_ddl)
            owner_id = poll_info.vote_owner
            op1 = poll_info.vote_op1
            op2 = poll_info.vote_op2
            op3 = poll_info.vote_op3
            op4 = poll_info.vote_op4
            poll_infomation = {'TimeStamp': TimeStamp, 'owner_id': owner_id, 'op1': op1, 'op2': op2, 'op3': op3,
                               'op4': op4}
            return jsonify(poll_infomation)
        else:
            return jsonify(None)
    elif request_type == 'poll_result':
        poll_result_data = session_db.query(PollResult).all()
        if poll_result_data:
            poll_result_data_dicts = [result.as_dict() for result in poll_result_data]
            print(poll_result_data_dicts)
            print(type(poll_result_data_dicts[0]))
            print('Poll Result sent successfully!')
            return jsonify(poll_result_data_dicts)
        return jsonify(None)
    else:
        return jsonify(None)







@server.route('/submit_register', methods=['POST'])
def submit_register():
    register_username = request.form.get('username')
    register_password = request.form.get('password')
    register_email = request.form.get('email')
    register_sex = request.form.get('sex')
    print(f"Register Information: Username - {register_username}, Email - {register_email}, Sex - {register_sex}")

    # 检查数据库中是否已存在相同用户名的用户
    existing_user = session_db.query(UserInfo).filter_by(username=register_username).first()
    if existing_user:
        message = f"Username '{register_username}' already exists. Registration rejected."
        print(message)
        return jsonify({'status': 'error', 'message': message}), 400
    else:
        new_user_info = UserInfo(
            username=register_username,
            password=register_password,
            e_mail=register_email,
            sex=register_sex
        )
        generator_instance = Generator()
        new_user_keys = generator_instance.generate_secret_keys()
        new_user_secret = UserSecret(
            username=register_username,
            password=register_password,
            private_key=new_user_keys['sk'],
            public_key=new_user_keys['pk']
        )

        try:
            session_db.add(new_user_info)
            session_db.add(new_user_secret)
            session_db.commit()
            return jsonify({'status': 'success', 'message': 'User Information and Secret registered successfully!'}), 200  # 返回包含成功消息的 JSON 格式响应
        except Exception as e:
            print(f'Failed to register user: {e}')
            session_db.rollback()
            return jsonify({'status': 'error', 'message': f'Failed to register user: {e}'}), 400


@server.route('/submit_poll', methods=['POST'])
def submit_poll():
    # 获取表单数据
    poll_title = request.form.get('pollTitle')
    poll_description = request.form.get('pollDescription')
    poll_deadline_str = request.form.get('deadline')
    poll_deadline = datetime.strptime(poll_deadline_str, '%Y-%m-%d %H:%M:%S')
    option_count = int(request.form.get('optionCount'))
    options = [request.form.get(f'option{i + 1}') for i in range(option_count)]
    if option_count < 4:
        for i in range(4-option_count):
            options.append('null')

    # 检查数据库中是否已存在相同用户名的用户
    existing_user = session_db.query(UserInfo).filter_by(username=poll_title).first()
    if existing_user:
        message = f"Poll '{poll_title}' already exists. Request rejected."
        print(message)
        return jsonify({'status': 'error', 'message': message}), 400

    new_TempPoll = TempPoll(
        vote_owner=1,


        vote_title=poll_title,
        vote_description=poll_description,
        vote_deadline=poll_deadline,
        vote_options_1=options[0],
        vote_options_2=options[1],
        vote_options_3=options[2],
        vote_options_4=options[3],
    )

    AdministratorCheckFlag = AdministratorCheck(new_TempPoll)

    new_CollectPoll = CollectPoll(
        vote_owner=1,



        vote_name=poll_title,
        vote_des=poll_description,
        vote_ddl=poll_deadline,
        vote_op1=options[0],
        vote_op2=options[1],
        vote_op3=options[2],
        vote_op4=options[3],
    )


    try:
        session_db.add(new_TempPoll)
        session_db.add(new_CollectPoll)
        session_db.commit()
        return jsonify({'status': 'success',
                        'message': 'User Information and Secret registered successfully!'}), 200  # 返回包含成功消息的 JSON 格式响应
    except Exception as e:
        print(f'Failed to register user: {e}')
        session_db.rollback()
        return jsonify({'status': 'error', 'message': f'Failed to register user: {e}'}), 400


@server.route('/calculate_result_submit', methods=['POST'])
def calculate_result_submit():
    calculate_data = request.get_json()
    calculate_poll_id = calculate_data.get('poll_id')
    calculate_result = calculate_data.get('result')
    calculate_valid_uservotes = calculate_data.get('uservotes')
    print(calculate_poll_id)
    print(calculate_result)
    print(calculate_valid_uservotes)
    new_poll_result = PollResult(poll_id=calculate_poll_id, op1_num=calculate_result[0], op2_num=calculate_result[1], op3_num=calculate_result[2],
                                 op4_num=calculate_result[3], invalid_num=calculate_result[4], total_num=calculate_result[5])
    session_db.add(new_poll_result)
    new_valid_uservotes = calculate_valid_uservotes
    # session_db.bulk_save_objects(new_valid_uservotes)

    session_db.commit()
    print('Calculate Result received successfully!')
    return 'success'


@server.route('/collect_poll')
def send_collect_poll():
    results = session_db.query(CollectPoll).all()
    data_list = []          # 将数据以字典列表的形式存放在data_list中
    for result in results:
        data_dict = {
            'vote_id': result.vote_id,
            'vote_owner': result.vote_owner,
            'vote_name': result.vote_name,
            'vote_des': result.vote_des,
            'vote_ddl': result.vote_ddl,
            'vote_op1': result.vote_op1,
            'vote_op2': result.vote_op2,
            'vote_op3': result.vote_op3,
            'vote_op4': result.vote_op4
        }
        data_list.append(data_dict)
    print(data_list)
    return jsonify({'poll_data': data_list})

def AdministratorCheck(poll_instance: TempPoll):
    # 审核
    return ADMINISTRATOR_PASS
    # return ADMINISTRATOR_REJECT



@server.route('/candidates/labels/')
def get_candidate_labels():
    data = bvm_machine.get_candidate_labels()
    return json.dumps({
        'data': data,
        'count': len(data),
        'status': OK
    })


@server.route('/vote/collect', methods=['POST'])
def vote():
    try:
        picked_candidate = flask.request.form['pick']
        vote_response = bvm_machine.vote(picked_candidate)
    except ValueError as e:
        return json.dumps({
            'status': NOT_FOUND,
            'description': str(e),
        })
    except KeyError as e:
        return json.dumps({
            'status': BAD_REQUEST,
            'description': str(e),
        })
    return json.dumps({
        'data': vote_response,
        'status': OK,
    })