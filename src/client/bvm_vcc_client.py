import json
import yaml
import requests
import flask
import ast
from flask import Flask, request, jsonify, session, redirect, url_for
import datetime
from src.bingovoting.booths import PedersenBooth
from ..cryptography.cryptofunction import cryptofunction
from ..bingovoting import function

from sqlalchemy import create_engine, MetaData, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

OK = 200
ACCEPTED = 202
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
NOT_ACCEPTABLE = 406

STOREVOTING_SUCCESS = 0
STOREVOTING_FAILED = 1

booth_client = flask.Flask(__name__)
try:
    with open('src/client/vcc_config.yml', 'r') as stream:
        config = yaml.safe_load(stream)
except FileNotFoundError:
    booth_client.logger.error('[client.py] Config file not found')
    exit()
bvm_booth = PedersenBooth(config)

my_cert = None
select_vote_id = None

Base = declarative_base()  # SQLAlchemy基类
uservotes_db = create_engine('sqlite:///uservotes.db', echo=True)
Session_uservotes = sessionmaker(bind=uservotes_db)
session_uservotes = Session_uservotes()


class UserVotes(Base):
    __tablename__ = 'UserVotes'
    vote_record_id = Column(Integer, primary_key=True)
    vote_id = Column(Integer, nullable=False)               # 某项投票的编号
    cert_id = Column(Integer, nullable=False)               # 投票有效编号
    encrypt_vote_data = Column(String, nullable=False)      # 用户投票加密数据
    encrypt_vote_content = Column(String, nullable=False)   # 未解密的投票内容
    TimeStamp = Column(Integer, nullable=False)            # 投票时间戳，整形


class PollInfo(Base):
    __tablename__ = 'PollInfo'
    poll_record_id = Column(Integer, primary_key=True)
    poll_id = Column(Integer, nullable=False)
    poll_owner_id = Column(Integer, nullable=False)
    TimeStamp = Column(Integer, nullable=False)
    op1 = Column(String, nullable=True)  # 必须有一个选项
    op2 = Column(String, nullable=False)
    op3 = Column(String, nullable=False)
    op4 = Column(String, nullable=False)

# 利用反射功能获取数据库中已有的表信息
metadata = MetaData()
metadata.reflect(bind=uservotes_db)

Base.metadata.create_all(uservotes_db)





@booth_client.route('/')
def index():
    server_poll_data = bvm_booth._bvm_uri('/collect_poll')
    try:
        response = requests.get(server_poll_data)
        if response.status_code == 200:
            poll_data = response.json()['poll_data']
        else:
            print('error, 无法连接到服务器')
            return {'error': '无法连接到服务器'}

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")

    print(poll_data)

    server_login = bvm_booth._bvm_uri('/login/cert')

    vote_data = []
    for data in poll_data:
        vote_data.append({'vote_id': data['vote_id'],
                          'vote_name': data['vote_name'],
                          'vote_des': data['vote_des'],
                          'vote_ddl': data['vote_ddl']})

    # vote_data.append({'vote_id': 1, 'vote_name': 'TestA', 'vote_des': 'this is a test poll', 'vote_ddl': datetime.datetime(2024, 4, 15, 12, 0, 0)})
    # vote_data.append({'vote_id': 2, 'vote_name': '最喜欢的教师', 'vote_des': '请为你最喜欢的教师投上一票', 'vote_ddl': datetime.datetime(2024, 4, 17, 18, 0, 0)})
    # vote_data.append({'vote_id': 3, 'vote_name': '补贴发放形式', 'vote_des': '选择食堂7折还是津贴发放？', 'vote_ddl': datetime.datetime(2024, 4, 19, 8, 0, 0)})
    # vote_data.append({'vote_id': 4, 'vote_name': '毕业去向调查', 'vote_des': '未来的道路是什么？你会做出什么选择？', 'vote_ddl': datetime.datetime(2024, 4, 30, 22, 0, 0)})

    # return jsonify(vote_data[1])
    return flask.render_template(
        'booth/index.html',
        vote_data=vote_data,
        server_login=server_login
    )

@booth_client.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':            # 无法及时在用户页面上展示
        message = request.get_json()
        print(message)
        return flask.render_template('./booth/register.html', message=message)
    else:
        server_submit_register = bvm_booth._bvm_uri('/submit_register')
        print(server_submit_register)
        return flask.render_template('./booth/register.html', submit_register=server_submit_register)

@booth_client.route('/vote', methods=['POST'])
def get_user_input():
    vote_option = request.form.get('voteOption')
    if vote_option == 'option1':
        result = '选项1'
    elif vote_option == 'option2':
        result = '选项2'
    else:
        result = '未知选项'

    response_data = {'message': '投票成功', 'result': result, 'data': vote_option}
    return jsonify(response_data)


@booth_client.route('/rec_cert', methods=['POST'])
def rec_cert():
    global my_cert
    my_cert = request.get_json()
    if my_cert == None:
        print('Server reject to assign cert for me')
        # 对页面进行一些处理
    print('Rec cert:', my_cert)

    # return redirect(url_for('process_vote'))
    return '0'


@booth_client.route('/rec_select_id', methods=['POST'])
def rec_select_id():
    data = request.get_json()
    vote_id = data.get('vote_id')
    global select_vote_id
    select_vote_id = int(vote_id)
    print(select_vote_id)
    print(type(select_vote_id))
    return '0'


@booth_client.route('/vote_option')
def vote_option():
    if my_cert == None:
        print()
        # 进行必要处理
        return '1'

    server_poll_data = bvm_booth._bvm_uri('/collect_poll')

    response = requests.get(server_poll_data)
    if response.status_code == 200:
        poll_data = response.json()['poll_data']
    else:
        print('error, 无法连接到服务器')
        return {'error': '无法连接到服务器'}

    for data in poll_data:
        if data['vote_id'] == select_vote_id:
            break

    print(data)

    return flask.render_template('./booth/vote_option.html', data=data)


@booth_client.route('/process_vote', methods=['POST'])
def process_vote():
    send_vote_data = {}         # Voter构造的发送数据
    vote_data = request.get_json()
    selected_option = vote_data.get('option')

    crypt_instance = cryptofunction()
    my_standard_cert = crypt_instance.generate_standard_cert(my_cert)
    ZKProof = crypt_instance.generate_ZKProof(my_standard_cert)     # 这里返回的ZKProof是一个元组，一个List对象和一个int对象组合
    # print(my_cert)
    # print(ZKProof)
    print(vote_data, '\n', selected_option)     # 收到某投票的选项描述信息

    # 验证零知识证明
    Confirm_ZKProof_Type = crypt_instance.Confirm_ZKProof(ZKProof, my_standard_cert[1])
    if Confirm_ZKProof_Type == crypt_instance.ZKProof_CONFIRM_SUCCESS:
        print('ZKProof confirm success!')
    elif Confirm_ZKProof_Type == crypt_instance.ZKProof_CONFIRM_FAILED:
        print('ZKProof confirm failed!')

    send_vote_data['Cert_No'] = 1
    send_vote_data['ZKProof'] = ZKProof
    send_vote_data['EncryptVoteContent'] = selected_option     # 待加密
    send_vote_data['TimeStamp'] = function.GetTimeStamp()          # datatime.datetime类型

    data = str(send_vote_data)
    Signature = crypt_instance.generate_signature(data, my_standard_cert[0])
    send_vote_data_with_signature = {'send_vote_data': data, 'signature': Signature}
    plaintext = str(send_vote_data_with_signature)
    # encrypt_vote_data = crypt_instance.encrypt_data(plaintext)
    encrypt_vote_data = plaintext

    # 验证签名
    Confirm_Signature_type = crypt_instance.confirm_signature(data, Signature, my_standard_cert[1])
    if Confirm_Signature_type == crypt_instance.Signature_CONFIRM_SUCCESS:
        print('Signature confirm success!')
    elif Confirm_Signature_type == crypt_instance.Signature_CONFIRM_FAILED:
        print('Signature confirm failed!')

    vcc_url = 'http://127.0.0.1:9002/vote_data_collect'
    vcc_response = requests.post(vcc_url, json=encrypt_vote_data)
    if vcc_response.status_code == 200:
        print('Vote data Sent successfully!')
    return '123'



### VCC module

@booth_client.route('/InitiatingPoll')      # 创建投票
def initaiting_poll():
    server_submit_poll = bvm_booth._bvm_uri('/submit_poll')
    return flask.render_template('./booth/InitiatingPoll.html', submit_poll=server_submit_poll)


@booth_client.route('/vote_data_collect', methods=['POST'])       # 接收Voter发送的投票数据
def vote_data_collect():
    encrypt_user_vote_data = request.get_json()
    print('User vote:', encrypt_user_vote_data)

    crypt_instance = cryptofunction()
    # decrypt_user_data = crypt_instance.decrypt_data(encrypt_user_vote_data)
    decrypt_user_data = encrypt_user_vote_data
    user_data_dictionary = ast.literal_eval(decrypt_user_data)

    user_vote_data = user_data_dictionary['send_vote_data']
    user_signature = user_data_dictionary['signature']
    print(user_vote_data)
    print(user_signature)

    vote_content = ast.literal_eval(user_vote_data)
    cert_id = vote_content.get('Cert_No')
    ZKProof = vote_content.get('ZKProof')
    EncryptVoteContent = vote_content.get('EncryptVoteContent')
    VoteContent = EncryptVoteContent        # 解密
    TimeStamp = vote_content.get('TimeStamp')

    cert_info = RequestForPKofCert(cert_id)   # 向服务器请求Voter的证书公钥
    if cert_info:       # 非空
        cert_pk = cert_info[0]
        vote_id = cert_info[1]
    else:
        print('没有正确收到证书公钥')
    print('cert_pk:', cert_pk)

    cert_pk_VerifyingKey = crypt_instance.Str2VerifyingKey(cert_pk)

    Confirm_Signature_Type = crypt_instance.confirm_signature(user_vote_data, user_signature, cert_pk_VerifyingKey)
    if Confirm_Signature_Type == crypt_instance.Signature_CONFIRM_FAILED:
        print('数字签名未通过')
        return 'failed'

    Confirm_ZKProof_Type = crypt_instance.Confirm_ZKProof(ZKProof, cert_pk_VerifyingKey)
    if Confirm_ZKProof_Type == crypt_instance.ZKProof_CONFIRM_FAILED:
        print('零知识验证未通过')
        return 'failed'
    # 完成上面两个验证，说明至少发送方有足够的信息构造一个选票
    poll_existing = session_uservotes.query(PollInfo).filter_by(poll_id=vote_id).first()
    if poll_existing==None:         # 新投票id的投票数据来了
        poll_info = RequestForPollInfo(vote_id)
        print('poll_info:', poll_info)
        if poll_info:
            print(poll_info)
            poll_TimeStamp = poll_info.get('TimeStamp')
            owner_id = poll_info.get('owner_id')
            op1 = poll_info.get('op1')
            op2 = poll_info.get('op2')
            op3 = poll_info.get('op3')
            op4 = poll_info.get('op4')
            new_poll_info = PollInfo(poll_id=vote_id, poll_owner_id=owner_id, TimeStamp=poll_TimeStamp, op1=op1, op2=op2, op3=op3, op4=op4)
            session_uservotes.add(new_poll_info)
            session_uservotes.commit()
        else:
            print('没有正确收到投票信息')
    else:
        poll_TimeStamp = poll_existing.TimeStamp

    Collect_Vote_Type = CheckStoreUserVoting(vote_id, cert_id, EncryptVoteContent, TimeStamp, encrypt_user_vote_data, poll_TimeStamp)
    if Collect_Vote_Type == STOREVOTING_FAILED:
        print('该证书已有投票数据存储，本投票拒绝接收')
        return 'failed'
    else:
        print('接收Voter发送的投票数据')
        return 'success'


@booth_client.route('/calculate_vote')
def calculate_vote():
    calculate_poll_id = 4       # 统计投票编号
    # 获取解密私钥 向CA
    # ...
    poll_info = session_uservotes.query(PollInfo).filter_by(poll_id=calculate_poll_id).first()
    uservotes = session_uservotes.query(UserVotes).filter_by(vote_id=calculate_poll_id).all()
    op1_num = 0
    op2_num = 0
    op3_num = 0
    op4_num = 0
    invalid_num = 0
    for vote in uservotes:
        # 解密
        vote_content = vote.encrypt_vote_content
        if vote_content == poll_info.op1:
            op1_num = op1_num + 1
        elif vote_content == poll_info.op2:
            op2_num = op2_num + 1
        elif vote_content == poll_info.op3:
            op3_num = op3_num + 1
        elif vote_content == poll_info.op4:
            op4_num = op4_num + 1
        else:
            invalid_num = invalid_num + 1
    total_num = op1_num + op2_num + op3_num + op4_num + invalid_num
    if poll_info.op2 == 'null':
        invalid_num = invalid_num + op2_num
        op2_num = 0
    if poll_info.op3 == 'null':
        invalid_num = invalid_num + op3_num
        op3_num = 0
    if poll_info.op4 == 'null':
        invalid_num = invalid_num + op4_num
        op4_num = 0

    calculate_result = (op1_num, op2_num, op3_num, op4_num, invalid_num, total_num)
    server_url = 'http://localhost:9000/calculate_result_submit'
    result_data = {'poll_id': calculate_poll_id, 'result': calculate_result}
    # result_data = {'poll_id': calculate_poll_id, 'result': calculate_result, 'uservotes': uservotes}
    response = requests.post(server_url, json=result_data)
    if response.status_code == 200:
        print('Calculate data sent successfully!')
    return '0'


def RequestForPKofCert(cert_id: int):
    server_url = 'http://localhost:9000/request_for_info'
    request_data = {'request_type': 'cert_pk', 'cert_id': cert_id}
    response = requests.post(server_url, json=request_data)
    if response.status_code == 200:
        result = response.json()
        return result                  # 同时返回cert_pk和vote_id
    else:
        return {'error': '无法连接到服务器'}


def RequestForPollInfo(vote_id):
    server_url = 'http://localhost:9000/request_for_info'
    request_data = {'request_type': 'poll_info', 'poll_id': vote_id}
    response = requests.post(server_url, json=request_data)
    print(request_data)
    if response.status_code == 200:
        print('CCCCCCCC')
        result = response.json()
        return result
    else:
        return {'error': '无法连接到服务器'}


def CheckStoreUserVoting(vote_id, cert_id, EncryptVoteContent, TimeStamp, encrypt_user_vote_data, poll_TimeStamp):
    new_user_vote = UserVotes(
        vote_id=vote_id,
        cert_id=cert_id,
        encrypt_vote_data=encrypt_user_vote_data,
        encrypt_vote_content=EncryptVoteContent,
        TimeStamp=TimeStamp
    )
    result = session_uservotes.query(UserVotes).filter_by(vote_id=vote_id, cert_id=cert_id).first()
    if result:          # 存在名录
        if TimeStamp < result.TimeStamp and TimeStamp < poll_TimeStamp:        # 此投票时间戳更早 且 没有超过投票截止事件
            session_uservotes.delete(result)
            session_uservotes.add(new_user_vote)        # 更新数据库
            session_uservotes.commit()
            return STOREVOTING_SUCCESS
        else:
            return STOREVOTING_FAILED           # 失败，已有更早的投票数据
    else:
        session_uservotes.add(new_user_vote)  # 更新数据库
        session_uservotes.commit()
        return STOREVOTING_SUCCESS


