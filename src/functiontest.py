from datetime import datetime
import ast

data = {
    'name': 'Alice',
    'age': 30,
    'email': 'alice@example.com',
    'city': 'New York'
}
str_data = str(data)
dictionary = ast.literal_eval(str_data)
print(data)
print(str_data)
print(dictionary)
tmp = dictionary.get('name')
# tmp2 = str_data['name']
tmp3 = dictionary['name']
tmp4 = dictionary.get('na')
tmp5 = 'None'
print(tmp)
print(tmp4)
if tmp4 == None:
    print('getFunction return NoneType')
def GetTimeStamp():
    # 获取当前时间
    current_time = datetime.now()

    # 将时间转换为时间戳（精确到秒）
    timestamp_sec = int(current_time.timestamp())
    print(timestamp_sec)
    datetime_obj = datetime.fromtimestamp(timestamp_sec)  # 需要除以1000转换成秒
    print(datetime_obj)
    a = DateTime2Int(datetime_obj)
    print(a)
    return datetime_obj


def DateTime2Int(datetime_obj: datetime):
    timestamp_sec = int(datetime_obj.timestamp())
    return timestamp_sec

GetTimeStamp()

dic3 = {'a': 'hello'}
dic2 = {'dic': dic3}
dic1 = {'dic': dic2}
a = str(dic1)
b = ast.literal_eval(a)
print(b)



