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
    with open('src/client/voter_config.yml', 'r') as stream:
        config = yaml.safe_load(stream)
except FileNotFoundError:
    booth_client.logger.error('[client.py] Config file not found')
    exit()
bvm_booth = PedersenBooth(config)

my_cert = None
my_cert_id = None
select_vote_id = None

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
    global my_cert_id
    cert = request.get_json()
    print(cert)
    if cert == None:
        print('Server reject to assign cert for me')
        # 对页面进行一些处理
    print('Rec cert:', my_cert)

    my_cert_id = cert[0]
    my_cert = cert[1]
    print('cert_id:', my_cert_id)
    print('cert_content:', my_cert)

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
        return flask.render_template('./booth/CertReject.html')

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
    print(my_standard_cert)
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

    send_vote_data['Cert_No'] = my_cert_id
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


@booth_client.route('/view_vote_result')
def view_vote_result():
    server_url = 'http://localhost:9000/request_for_info'
    request_data = {'request_type': 'poll_result'}
    response = requests.post(server_url, json=request_data)
    if response.status_code == 200:
        poll_results = response.json()
        print(type(poll_results))
        print(poll_results)
        # for poll_result in poll_results:

        return flask.render_template('./booth/vote_result.html', poll_results=poll_results)




    else:
        return {'error': '无法连接到服务器'}
    return '0'

################

@booth_client.route('/InitiatingPoll')      # 创建投票
def initaiting_poll():
    server_submit_poll = bvm_booth._bvm_uri('/submit_poll')
    return flask.render_template('./booth/InitiatingPoll.html', submit_poll=server_submit_poll)


@booth_client.route('/vote_data_collect')       # 接收Voter发送的投票数据
def vote_data_collect():
    encrypt_user_vote_data = request.get_json()
    print('User vote:', encrypt_user_vote_data)

    crypt_instance = cryptofunction()
    # decrypt_user_data = crypt_instance.decrypt_data(encrypt_user_vote_data)
    decrypt_user_data = encrypt_user_vote_data
    user_data_dictionary = ast.literal_eval(decrypt_user_data)

    user_vote_data = user_data_dictionary['send_vote_data']
    user_signature = user_data_dictionary['signature']

    vote_content = ast.literal_eval(user_vote_data)
    cert_id = vote_content.get('Cert_No')
    ZKProof = vote_content.get('ZKProof')
    EncryptVoteContent = vote_content.get('EncryptVoteContent')
    VoteContent = EncryptVoteContent        # 解密
    TimeStamp = vote_content.get('TimeStamp')

    cert_pk = RequestForPKofCert(cert_id)   # 向服务器请求Voter的证书公钥

    cert_pk_VerifyingKey = crypt_instance.Str2VerifyingKey(cert_pk)

    Confirm_Signature_Type = crypt_instance.confirm_signature(user_vote_data, user_signature, cert_pk_VerifyingKey)
    if Confirm_Signature_Type == crypt_instance.Signature_CONFIRM_FAILED:
        print('数字签名未通过')
        return 'failed'

    Confirm_ZKProof_Type = crypt_instance.Confirm_ZKProof(ZKProof, cert_pk_VerifyingKey)
    if Confirm_ZKProof_Type == crypt_instance.ZKProof_CONFIRM_FAILED:
        print('零知识验证未通过')
        return 'failed'

    Collect_Vote_Type = StoreUserVoting(VoteContent, TimeStamp)
    if Collect_Vote_Type == STOREVOTING_FAILED:
        print('该证书已有投票数据存储，本投票拒绝接收')
        return 'failed'








@booth_client.route('/data')
def get_data():
    data = {'message': 'Hello from server!'}

    return jsonify(data)

@booth_client.route('/data_test')
def data_test():
    return flask.render_template('./booth/js_getdata.html')


@booth_client.route('/vote/form/')
def open_vote_form():
    candidate_labels = bvm_booth.get_candidate_labels()
    return flask.render_template(
        'booth/vote_form.html',
        send_vote_uri=flask.url_for('send_vote'),
        candidate_labels=candidate_labels,
    )

@booth_client.route('/vote/form/send', methods=['POST'])
def send_vote():
    response = bvm_booth.send_vote(flask.request.form['pick'])
    ballot_data = response['data']['ballot']
    ballot_id = response['data']['id']
    accepted = response['data']['accepted']
    return flask.render_template(
        'booth/ballot.html',
        home_uri=flask.url_for('index'),
        accepted=accepted,
        ballot_data=ballot_data,
        id=ballot_id,
    )

def RequestForPKofCert(cert_id: int):
    server_url = 'http://localhost:9000/request_for_pk'
    request_data = {}
    request_data.append({'request_type': 'cert_pk', 'cert_id': cert_id})
    response = requests.post(server_url, json=request_data)
    if response.status_code == 200:
        cert_pk = response.json()['cert_pk']
        return cert_pk
    else:
        return {'error': '无法连接到服务器'}

def StoreUserVoting(Vote_content, TimeStamp):
    return STOREVOTING_SUCCESS