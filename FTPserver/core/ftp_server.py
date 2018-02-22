import socketserver
import configparser
from conf import settings
import os,subprocess
import hashlib
import re

STATUS_CODE  = {
    200 : "Task finished",  # 任务完成
    250 : "Invalid cmd format, e.g: {'action':'get','filename':'test.py','size':344}", #错误格式
    251 : "Invalid cmd ", #无效命令
    252 : "Invalid auth data",  #无效认证数据
    253 : "Wrong username or password",  #用户名密码错误
    254 : "Passed authentication",  #通过认证
    255 : "Filename doesn't provided",  #文件名未提供
    256 : "File doesn't exist on server", #服务器上不存在文件
    257 : "ready to send file",  #准备发送文件
    288 : "你可以发文件了",
    258 : "md5 verification",  #MD5验证
    259 : "path doesn't exist on server", #路径不存在于服务器上
    260 : "path changed", # 路径改变
    261: "Not a directory",
    262: "Permission denied",
    263: "Print working directory error",
    264: "Ready to send data",
    265: "Put: overwrite",
    266: "Ready to receive file",
    267: "The file is consistent",
    268: "The file is not consistent",
    270: "Remove file error",
    271: "It is not a file",
    272: "Filename doesn't provided",
    273: "Create directory error",
    275: "File or directory exists",
    276: "Remove directory error",
    277: "Directory not exists",
}

import json
class FTPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        while True:
            # 接受数据
            self.data = self.request.recv(1024).strip()
            # 打印出客户端地址
            print(self.client_address[0])
            # 打印接受的数据
            print(self.data)
            # 如果 data 没有数据 表明客户端已经断开
            if not self.data:
                print("client closed...")
                break
            # 因为data 是json 的dumps的数据格式 。所以 需要loads
            data  = json.loads(self.data.decode())
            # 获取data 中的action 不为空
            if data.get('action') is not None:
                #print("---->",hasattr(self,"_auth"))
                # 检查字符串是否存在于这个类方法中
                if hasattr(self,"_%s"%data.get('action')):
                    # 获取 action对应的类方法的内存地址
                    func = getattr(self,"_%s"% data.get('action'))
                    # 执行这个方法 把data 传了过去
                    func(data)
                else:
                    # 无效命令
                    print("invalid cmd")
                    # 向客户端返回一个状态信息
                    self.send_response(251)
            else:
                # 格式错误
                print("invalid cmd format")
                # 向客户端返回一个状态信息
                self.send_response(250)

    def send_response(self,status_code,data=None):
        '''向客户端返回数据'''
        # response 就是一个 返回状态码
        response = {'status_code':status_code,
                    'status_msg':STATUS_CODE[status_code],
                    }
        #print("data",data)
        # 如果data 有数据
        if data:
            #print("goes here....")
            response.update( { 'data': data  })  # 就向字典中添加一行data 数据
        #print("-->data to client",response)
        # 如果是没有传data 就传递的格式就是单纯的一个状态码。
        # 如果有传了data  传递的格式里面就有data 数据 ，data 是一个json 的一个数据
        self.request.send(json.dumps(response).encode())  #

    def _auth(self,*args,**kwargs):
        # data 就是第一个数据 相当于 调用 _auth(self,data)
        data = args[0]
        # 如果 username 为空 或者密码为空
        if data.get("username") is None or data.get("password") is None:
            # 就发送一个无效认证数据
            self.send_response(252)

        # user 就是返回一个用户名。或者返回一个空
        user =self.authenticate(data.get("username"),data.get("password"))
        # 如果 用户名 为空
        if user is None:
            #就发送一个用户名密码错误
            self.send_response(253)
        # 如果user 不为空，说明用户名密码是对的
        else:
            # 打印出用户名
            print("passed authentication",user)
            # 添加到一个变量中
            self.user = user
            # 就是相当于在配置文件中添加一行username
            self.user['username'] =  data.get("username")

            # 用户的家目录
            self.home_dir = "%s/home/%s" %(settings.BASE_DIR,data.get("username"))
            #所在目录
            self.current_dir = self.home_dir
            # 发送一个254 的正确通过
            self.send_response(254)


    def authenticate(self,username,password):
        '''验证用户合法性，合法就返回用户数据'''

        config = configparser.ConfigParser()
        config.read(settings.ACCOUNT_FILE)
        # username 是在子节点
        if username in config.sections():
            # password 是子节点中的[Password]
            _password = config[username]["Password"]
            # 如果密码等于 配置文件中的密码
            if _password == password:
                print("pass auth..",username)
                #如果没有问题，就添加一行 用户名
                config[username]["Username"] = username
                # 返回一个用户名，如果没有的话就返回一个空
                return config[username]

    # def _put(self,*args,**kwargs):
    #     "client send file to server"
    #     pass

    def _listdir(self,*args,**kwargs):
        """return file list on current dir"""
        # 列出所在目录的文件
        res = self.run_cmd("ls -lsh %s" %self.current_dir)

        ##传递一个任务完成。并且传递一个data 不为空 data 传递是一个ls 的用户列出的
        self.send_response(200, data=res)
        # 客户端会接受到 一个200 的 和 ls 列出的东西

    def run_cmd(self,cmd):
        # 以shell 方式输出
        cmd_res = subprocess.getstatusoutput(cmd)
        # 输出的是元组的方式
        return cmd_res

    def _change_dir(self, *args,**kwargs):
        # 改变目录
        """change dir"""
        # 改变目录应该是cd 命令 *args 是一个 目录，或者是 ..
        # 如果 args[0] 有数据
        if args[0]:
            # 定义一个目录  dest_path 是家家目录和输入的目录
            dest_path = "%s/%s" % (self.current_dir,args[0]['path'] )
        else:
            # 如果没有就把家目录定义为dest_path
            dest_path = self.home_dir
        #print("dest path",dest_path)

        #真实的目录 返回 dest_path 的真实路径
        real_path = os.path.realpath(dest_path)
        # 打印出真实路径
        print("readl path ", real_path)
        # 查看 是否 是真实目录的开头  self.home_dir 就两种方式。一个是家目录，一个是家目录下面的
        if real_path.startswith(self.home_dir):# accessable
            # 判断是否是一个目录
            if os.path.isdir(real_path):
                # 如果是一个目录，那么 所在目录变为 真实目录
                self.current_dir = real_path
                # 返回 当前 用户的相对路径
                current_relative_dir = self.get_relative_path(self.current_dir)
                # 发送 一个260 和用户的相对路径
                self.send_response(260, {'current_path':current_relative_dir})

            else:
                # 发送一个路径不存在于服务器上
                self.send_response(259)
        else:
            # 如果头部信息不是 用户目录下 ，那么就没有权限
            print("has no permission....to access ",real_path)
            # 用户相对路径
            current_relative_dir = self.get_relative_path(self.current_dir)
            # 发送一个260 再发送一个 相对路径
            self.send_response(260, {'current_path': current_relative_dir})

    def get_relative_path(self,abs_path):
        # 返回此用户的相对路径
        # 把 前面的 BASE_DIR 去掉  只留下 abs_path的相对路径
        relative_path = re.sub("^%s"%settings.BASE_DIR, '', abs_path)
        # 打印出  相对路径。绝对路径
        print(("relative path",relative_path,abs_path))
        # 返回相对路径
        return relative_path

    def _pwd(self,*args,**kwargs):
        #显示用户的当前目录
        # current_relative_dir 显示当前用户的相对路径
        current_relative_dir = self.get_relative_path(self.current_dir)
        # 发送一个200 并且data 对应是一个相对路径
        self.send_response(200,data=current_relative_dir)
    def _put(self, *args, **kwargs):
        '''
        客户端上传文件
        :param args:
        :param kwargs:
        :return:
        '''
        data = args[0]
        file_abs_path = "{}/{}".format(self.home_dir, data.get("filename"))

        # print(self.user)

        self.send_response(288)
        file_size = json.loads(self.request.recv(1024).decode())
        if file_size:  # 客户端准备传输文件
            self.request.send(b'1')
            received_size = 0
            file_obj = open(file_abs_path, "wb")
            if data.get('md5'):
                md5_obj = hashlib.md5()
                while received_size < file_size["file_size"]:
                    data = self.request.recv(4096)
                    received_size += len(data)
                    file_obj.write(data)
                    md5_obj.update(data)
                else:
                    print("---- file received ----")
                    file_obj.close()
                    self.request.send(b'1')  # 解决粘包
                    md5_val = md5_obj.hexdigest()
                    md5_from_client = json.loads(self.request.recv(1024).decode())
                    if md5_from_client['md5'] == md5_val:
                        self.send_response(267)
                    else:
                        self.send_response(268)
            else:
                while received_size < file_size["file_size"]:
                    data = self.request.recv(4096)
                    received_size += len(data)
                    file_obj.write(data)

    def _put2(self,*args,**kwargs):
        data=args[0]

        client_recv = json.loads(self.request.recv(1024).decode())
        print("准备发送文件")
        if client_recv('filename') is None:
            self.send_response(255)
            exit("error")
        file_size=client_recv('filesize')
        if file_size is None:
            self.send_response(255)
            exit("error")
        self.send_response(288)
        print("你可以发送文件了")
        file_abs_path = "%s/%s" % (self.current_dir, data.get('filename'))
        print("file abs path", file_abs_path)
        if os.path.isfile(file_abs_path):
            f=open(file_abs_path,"wb")
        else:
            f=open(file_abs_path,"wb")
        received_size=0
        cmd_res = b''

        while received_size < file_size:
            data=self.request.recv(1024)
            received_size += len(data)
            cmd_res += data
        else:
            f.close()
            print("文件接收完毕!!!")
            f.write(cmd_res)


    def _get(self,*args,**kwargs):
        # 从服务器拉取数据到本地
        # args 就是传递过来的一个json格式 数据
        data = args[0]
        # 如果接受到的data.中的filename 为空
        if data.get('filename') is None:
            # 就发送一个255  文件名未提供
            self.send_response(255)
        # file_abs 绝对路径就是 相当于/home/用户名/filename
        # 就是文件的绝对路径。
        file_abs_path = "%s/%s" %(self.current_dir,data.get('filename'))
        # 打印 出 file abs 目录
        print("file abs path",file_abs_path)

        # 如果文件存在
        if os.path.isfile(file_abs_path):
            # 打开这个文件
            file_obj = open(file_abs_path,"rb")
            #返回文件大小
            file_size = os.path.getsize(file_abs_path)
            # 发送一个257 加上文件大小
            self.send_response(257,data={'file_size':file_size})
            # 等待客户端确认
            self.request.recv(1) #等待客户端确认

            # 如果接受到md5
            if data.get('md5'):

                md5_obj = hashlib.md5()
                # 一行行吧文件发过去，md5 加密
                for line in file_obj:
                    self.request.send(line)
                    md5_obj.update(line)
                # 如果好了就关闭文件
                else:
                    file_obj.close()
                    # md5_val 等于文件的md5
                    md5_val = md5_obj.hexdigest()
                    # 发送 258 并且 发送md5
                    self.send_response(258,{'md5':md5_val})
                    print("send file done....")
            else:
                # 如果没有用md5加密
                # 打开文件
                for line in file_obj:
                    # 发送数据过去
                    self.request.send(line)
                else:
                    # 发送完毕之后 关闭文件
                    file_obj.close()
                    print("send file done....")
        else:
            # 文件不存在
            self.send_response(256)



if __name__ == "__main__":
    HOST, PORT = "localhost", 9500
