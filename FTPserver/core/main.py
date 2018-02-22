import optparse
from core.ftp_server import FTPHandler
import socketserver
from conf import settings
class ArvgHandler(object):
    def __init__(self):
        self.parser = optparse.OptionParser()
        (options, args) = self.parser.parse_args()
        self.verify_args(options, args)
    def verify_args(self,options,args):
        '''校验并调用相应的功能'''
        if args:
            if hasattr(self,args[0]):
                print(args[0])
                func = getattr(self,args[0])
                func()
            else:
                exit("usage:start/stop")
        else:
            exit("usage:start/stop")
    def start(self):
        print('---\033[32;1mStarting FTP server on %s:%s\033[0m----' %(settings.HOST, settings.PORT))
        server = socketserver.ThreadingTCPServer((settings.HOST, settings.PORT), FTPHandler)
        server.serve_forever()




