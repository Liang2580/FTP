import socket
import os ,json
import optparse
import getpass
import hashlib
import sys 

# 状态码
STATUS_CODE  = {
    250 : "Invalid cmd format, e.g: {'action':'get','filename':'test.py','size':344}", # 错误 格式
    251 : "Invalid cmd ",  #  错误命令
    252 : "Invalid auth data",  # 验证失败
    253 : "Wrong username or password",  # 用户名或者密码错误
    254 : "Passed authentication",  # 验证错误
}



class FTPClient(object):
    def __init__(self):

        # 临时user
        self.user = None

        # 创建parser实例
        parser = optparse.OptionParser()
        #添加 选项
        parser.add_option("-s","--server", dest="server", help="ftp server ip_addr")
        parser.add_option("-P","--port",type="int", dest="port", help="ftp server port")
        parser.add_option("-u","--username", dest="username", help="username")
        parser.add_option("-p","--password", dest="password", help="password")

        self.options , self.args = parser.parse_args()
        #校验合法性
        self.verify_args(self.options,self.args)
        # 创建链接
        self.make_connection()

    def make_connection(self):
        ''' 创建连接 '''
        self.sock = socket.socket()
        self.sock.connect((self.options.server,self.options.port))

    def verify_args(self, options,args):
        '''校验参数合法型'''

        if options.username is not None and options.password is not None:
            pass
        elif options.username is None and options.password is None:
            pass
        else:
            #options.username is None or options.password is None:
            exit("Err: username and password must be provided together..")

        if options.server and options.port:
            #print(options)
            if options.port >0 and options.port <65535:
                return True
            else:
                exit("Err:host port must in 0-65535")
        else:
            exit("Error:must supply ftp server address, use -h to check all available arguments.")

    def authenticate(self):
        '''用户验证'''
        if self.options.username:
            print(self.options.username,self.options.password)
            return  self.get_auth_result(self.options.username, self.options.password)
        else:
            retry_count = 0
            while retry_count <3:
                username = input("username:").strip()
                password = input("password:").strip()
                if self.get_auth_result(username,password):
                    return True
                retry_count += 1



    def get_auth_result(self,user,password):
        data = {'action':'auth',
                'username':user,
                'password':password}
        self.sock.send(json.dumps(data).encode())
        response = self.get_response()

        if response.get('status_code') == 254:
            print("Passed authentication!")
            self.user = user
            return True
        else:
            print(response.get("status_msg"))

    def get_response(self):
        '''得到服务器端回复结果'''
        data = self.sock.recv(1024)
        #print("server res", data)
        data = json.loads(data.decode())
        return data



    def interactive(self):
        if self.authenticate():
            print("---start interactive with u...")
            self.terminal_display = "[%s]$:"%self.user
            while True:
                choice = input(self.terminal_display).strip()
                if len(choice) == 0:continue

                cmd_list = choice.split()
                print(cmd_list )
                if hasattr(self,"_%s"%cmd_list[0]):

                    func = getattr(self,"_%s"%cmd_list[0])
                    func(cmd_list)
                else:
                    print("Invalid cmd,type 'help' to check available commands. ")
    
    def __md5_required(self,cmd_list):
        '''检测命令是否需要进行MD5验证'''
        if '--md5' in cmd_list:
            return True


    def _help(self,*args,**kwargs):
        supported_actions = """
        get filename    #get file from FTP server
        put filename    #upload file to FTP server
        ls              #list files in current dir on FTP server
        pwd             #check current path on server
        cd path         #change directory , same usage as linux cd command
        """
        print(supported_actions)

    def show_progress(self,total):
        received_size = 0 
        current_percent = 0 
        while received_size < total:
             if int((received_size / total) * 100 )   > current_percent :
                  print("#",end="",flush=True)
                  current_percent = int((received_size / total) * 100 )
             new_size = yield 
             received_size += new_size

    def _cd(self,*args,**kwargs):
        #print("cd args",args)
        if len(args[0]) >1:
            path = args[0][1]
        else:
            path = ''
        data = {'action': 'change_dir','path':path}
        self.sock.send(json.dumps(data).encode())
        response = self.get_response()
        if response.get("status_code") == 260:
            self.terminal_display ="%s:" % response.get('data').get("current_path")


    def _pwd(self,*args,**kwargs):
        data = {'action':'pwd'}
        self.sock.send(json.dumps(data).encode())
        response = self.get_response()
        has_err = False
        if response.get("status_code") == 200:
            data = response.get("data")

            if data:
                print(data)
            else:
                has_err = True
        else:
            has_err = True

        if has_err:
            print("Error:something wrong.")

    def _ls(self,*args,**kwargs):
        data = {'action':'listdir'}
        self.sock.send(json.dumps(data).encode())
        response = self.get_response()
        has_err = False
        if response.get("status_code") == 200:
            data = response.get("data")

            if data:
                print(data[1])
            else:
                has_err = True
        else:
            has_err = True

        if has_err:
            print("Error:something wrong.")

    def get_abs_path(self, *args, **kwargs):
        '''
        获取当前目录绝对路径
        :return:
        '''
        abs_path = os.getcwd()
        return abs_path

    def _put(self, cmd_list):
        '''
        客户端上传文件
        :param args:
        :param kwargs:
        :return:
        '''
        if len(cmd_list) == 1:  # 需要接文件名
            print("No filename follows.")
            return

        # 判断上传文件绝对路径或相对路径
        abs_path = self.get_abs_path()
        if cmd_list[1].startswith("/"):
            file_abs_path = cmd_list[1]
        else:
            file_abs_path = "{}/{}".format(abs_path, cmd_list[1])
        print("File abs path", file_abs_path)

        # 文件不存在时
        if not os.path.isfile(file_abs_path):
            print(STATUS_CODE[260])
            return

        # 提取文件名
        base_filename = cmd_list[1].split('/')[-1]

        data_header = {
            'action': 'put',
            'filename': base_filename
        }

        # 是否md5验证
        if self.__md5_required(cmd_list):
            data_header['md5'] = True

        self.sock.send(json.dumps(data_header).encode())
        response = self.get_response()

        if response["status_code"] == 288:  # 服务端准备接收文件
            print("---- ready to send file ----")
            file_obj = open(file_abs_path, "rb")
            file_size = os.path.getsize(file_abs_path)
            self.sock.send(json.dumps({'file_size': file_size}).encode())
            self.sock.recv(1)  # 等待客户端确认

            if data_header.get('md5'):
                md5_obj = hashlib.md5()
                for line in file_obj:
                    self.sock.send(line)
                    md5_obj.update(line)
                else:
                    file_obj.close()
                    self.sock.recv(1)  # 解决粘包
                    print(STATUS_CODE[258])
                    md5_val = md5_obj.hexdigest()
                    self.sock.send(json.dumps({'md5': md5_val}).encode())
                    md5_response = self.get_response()
                    if md5_response['status_code'] == 267:
                        print("[%s] %s!" % (base_filename, STATUS_CODE[267]))
                    else:
                        print("[%s] %s!" % (base_filename, STATUS_CODE[268]))
                    print("Send file done.")
            else:
                for line in file_obj:
                    self.sock.send(line)
                else:
                    file_obj.close()
                    print("Send file done.")
        else:
            print(STATUS_CODE[256])
    def _put2(self,cmd_list):
        print("put--",cmd_list)
        if len(cmd_list)==1:
            print("请输入正确的文件")
            return
        filename=cmd_list[-1]
        print(filename)
        if os.path.isfile(filename):
            file_size=os.path.getsize(filename)
            data_header={
                'action':'put',
                'filename':filename,
                'filesize':file_size,
            }
            # if self.__md5_required(cmd_list):
            #     data_header['md5'] = True
            print("准备发送文件了")
            self.sock.send(json.dumps(data_header).encode())
            response = self.get_response()
            print("接受服务端相应")
            print(response)
            if response["status_code"] == 288:
                print("aa")
                received_size = 0
                received_data=b''
                print(file_size)
                while  received_size < file_size:
                    f=open(filename,"rb")
                    for line in f:
                        self.sock.send(line)
                        received_size+=len(line)
                        received_data+=line
                    else:
                        print("OK")
                        f.close()
        else:
            print("not is exists")

    def _get(self,cmd_list):
        print("get--",cmd_list)
        # cmd_list 是一个列表 ['get','filename']
        if len(cmd_list) == 1:
            print("no filename follows...")
            return
        data_header = {
            'action':'get',
            'filename':cmd_list[1]
        }
        if self.__md5_required(cmd_list):
            data_header['md5'] = True

        self.sock.send(json.dumps(data_header).encode())
        response = self.get_response()
        print(response)
        if response["status_code"] == 257:#ready to receive
            self.sock.send(b'1')#send confirmation to server 
            base_filename = cmd_list[1].split('/')[-1]
            received_size = 0
            file_obj = open(base_filename,"wb")
            if response['data']['file_size'] == 0:
                file_obj.close()
                return

            if self.__md5_required(cmd_list):
                md5_obj = hashlib.md5()
                progress = self.show_progress(response['data']['file_size']) #generator
                progress.__next__()
                while received_size < response['data']['file_size']:
                    data = self.sock.recv(4096)
                    received_size += len(data)
                    try:
                      progress.send(len(data))
                    except StopIteration as e:
                      print("100%")
                    file_obj.write(data)
                    md5_obj.update(data)
                else:
                    print("----->file recv done----")
                    file_obj.close()
                    md5_val = md5_obj.hexdigest()
                    md5_from_server = self.get_response()
                    if md5_from_server['status_code'] == 258:
                        if md5_from_server['md5'] == md5_val:
                            print("%s 文件一致性校验成功!" % base_filename)
                    #print(md5_val,md5_from_server)

            else:
                progress = self.show_progress(response['data']['file_size']) #generator
                progress.__next__()

                while received_size < response['data']['file_size']:
                    data = self.sock.recv(4096)
                    received_size += len(data)
                    file_obj.write(data)
                    try:
                      progress.send(len(data))
                    except StopIteration as e:
                      print("100%")

                else:
                    print("----->file rece done----")
                    file_obj.close()

if __name__ == "__main__":
    ftp = FTPClient()
    ftp.interactive() #交互
