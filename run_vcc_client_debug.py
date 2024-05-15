import os
import pydevd_pycharm

from src.client.bvm_vcc_client import booth_client, config

# pydevd_pycharm.settrace('192.168.125.10', port=3000, stdoutToServer=True, stderrToServer=True)

# ptvsd.enable_attach("your_secret", address=('0.0.0.0', 3000))
# ptvsd.wait_for_attach()


if __name__ == '__main__':
    os.environ['FLASK_ENV']='development'
    ip = config['client_ip']
    port = config['client_port']
    booth_client.run(ip, port, debug=True)
