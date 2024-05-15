import requests

# 定义服务器端的URL地址
server_url = 'http://localhost:9000/submit_data'

# 用户输入的数据
user_data = {
    'name': 'John Doe',
    'age': 30,
    'email': 'johndoe@example.com'
}

# 发送数据到服务器
response = requests.post(server_url, json=user_data)

# 检查响应状态码
if response.status_code == 200:
    print('Data sent successfully!')
else:
    print('Failed to send data!')
