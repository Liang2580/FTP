
#这是一个python 的FTP的一个小玩意

运行的话。 Server 端的方式是这样的

python3 FTPServer/bin/ftp_server.py start 

### start 是启动的方式 


客户端连接的话

[root@salt_client FTP]# python3 FTPClient/ftp_client.py -s 127.0.0.1 -P9999 -uliang -pabc123

 默认的账户密码 liang  abc123
参数解释一下 
-s 代表服务器IP地址
-P 端口
-u 用户名
-p 密码


具有上传
下载
不行就进去help
[liang]$:help
['help']

        get filename    #get file from FTP server
        put filename    #upload file to FTP server
        ls              #list files in current dir on FTP server
        pwd             #check current path on server
        cd path         #change directory , same usage as linux cd command
        
[liang]$:

