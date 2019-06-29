from configparser import ConfigParser

config = ConfigParser()

config['setings'] = {

    'token' : r'YourTokenHere',
    'logServer' : 'LogSrverIdHere'
    'FBServer' : 'FBServerIdHere'

}

with open('cfg.ini', 'w') as f:

    config.write(f)
