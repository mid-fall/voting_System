import os

from src.server.bvm_server import server, config

if __name__ == '__main__':
    os.environ['FLASK_ENV']='development'
    ip = config['ip']
    port = config['port']
    server.run(ip, port, debug=True)