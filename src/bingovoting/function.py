from datetime import datetime

def GetTimeStamp():
    # 获取当前时间
    current_time = datetime.now()

    # 将时间转换为时间戳（精确到秒）
    timestamp_sec = int(current_time.timestamp())

    datetime_obj = datetime.fromtimestamp(timestamp_sec)

    # return datetime_obj
    return timestamp_sec

def DateTime2Int(datetime_obj: datetime):
    timestamp_sec = int(datetime_obj.timestamp())
    return timestamp_sec

