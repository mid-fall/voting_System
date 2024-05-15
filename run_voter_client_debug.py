import os

from src.client.bvm_voter_client import booth_client, config

if __name__ == '__main__':
    os.environ['FLASK_ENV']='development'
    ip = config['client_ip']
    port = config['client_port']
    booth_client.run(ip, port, debug=True)