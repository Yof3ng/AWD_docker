
# 打造一个集web和pwn于一体的AWD docker

## 安装docker

> 之前已经讲过docker怎么安装，网上也有很多教程，`sudo apt-get install docker.io`，这里就不赘述了。

## 拉取具有web环境的image

> 通过`sudo docker search lamp`，我们可以查找到有lamp集成环境的他人上传的image：
>
> ![](https://raw.githubusercontent.com/Yof3ng/images/master/img/20181103224056.png)
>
> 于是我选择了 tutum/lamp这个image。
>
> 使用命令：`sudo docker pull tutum/lamp`，将image拉取到本地后，使用命令`sudo docker images`查看：
>
> ![](https://raw.githubusercontent.com/Yof3ng/images/master/img/20181103224557.png)

## 将CTF_xinetd框架的dockerfile进行修改

> 修改如下:
>
> * 将原来的`FORM ubuntu:16.04`改为`FROM tutum/lamp`即之前拉取下来的具有web环境的image。
>
> * 添加`RUN apt-get -y install openssh-server`为ssh连接做准备。
> * 添加awd参赛者用户`RUN useradd -u 544  -g users -s /bin/bash -m awduser`
> * 添加html目录下的web题源码:`COPY ./html/ /var/www/html/web/`
> * 配置ssh远程连接：`COPY ./sshd_config.txt /etc/ssh/sshd_config`

```dockerfile
FROM tutum/lamp

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y lib32z1 xinetd
RUN apt-get -y install openssh-server

RUN useradd -m ctf
RUN useradd -u 544  -g users -s /bin/bash -m awduser
WORKDIR /home/

RUN cp -R /lib* /home/ctf && \
    cp -R /usr/lib* /home/ctf

RUN mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

RUN mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin && \
	cp /bin/bash /home/ctf/bin && \
	cp /bin/nc /home/ctf/bin && \
	cp /usr/bin/git /home/ctf/bin
	
COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

RUN chmod +x /start.sh

COPY ./html/ /var/www/html/web/
COPY ./bin/ /home/ctf/
COPY ./sshd_config.txt /etc/ssh/sshd_config
RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod 740 /home/ctf/flag
    
RUN service ssh start
CMD ["/start.sh"]
CMD ["/run.sh"]

EXPOSE 9999
```

附上sshd_config配置：

```bash

#	$OpenBSD: sshd_config,v 1.102 2018/02/16 02:32:40 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server

```

> 此时ctf_xinetd文件夹下的情况大致如下：
>
> ![](https://raw.githubusercontent.com/Yof3ng/images/master/img/20181103225916.png)
>
> bin文件夹用于放置 pwn题的binary程序和flag，html文件夹用于放置web_php环境的源码。

## Docker build

> 配置好了Dockerfile，以及bin文件夹和html文件夹后，需要注意ctf_xinetd配置文件中的binary程序名需要与bin文件夹中的binary程序名保持一致，这个参照ctf_xinetd说明书即可。

切换目录到与dockerfile同一目录，执行命令:`docker build -t imagename .`

实例：`docker build -t "awd1test" .`

等待dockerfile执行完毕之后就得到了一个定制的image:

![](https://raw.githubusercontent.com/Yof3ng/images/master/img/20181103230536.png)

## Docker Run

> 得到定制的image后，就是生成container了：
>
> 执行命令`sudo docker run -d -p 18080:80 -p 13306:3306 -p 10022:22 -p 19999:9999 -h "awd1test" --name="awd1test" awd1test`
>
> * 18080:80表示把docker环境的80端口映射到主机的18080端口
> * 13306:3306表示把docker环境的mysql服务映射到主机13306端口
> * 10022:22表示映射ssh服务
> * 19999:9999表示映射pwn题服务

执行命令之后，通过`sudo docker ps`查看正在运行的docker状态：

![](https://raw.githubusercontent.com/Yof3ng/images/master/img/20181103231044.png)

## 配置

> 执行命令`sudo docker exec -ti 15d94d229fcb /bin/bash`进入容器。

进入容器之后首先：

* 通过`passwd`命令设置root用户的密码以及awduser用户的密码，并且开启ssh远程连接服务，以便运维和awd参赛者的连接。
* 初始状态，mysql的root账户是没有密码的，所以需要手动为root添加密码`mysql> set password for root@localhost = password('root');`，分发给参赛者的账户为admin，密码随机生成。
* 若有mysql数据库需要加载，则使用类似``source /var/www/html/web/tcho.sql;`命令来加载sql脚本文件。
* 添加参赛者数据库用户：`mysql> insert into mysql.user(Host,User,Password) values("%","awduser",password("123456"));`

关于具体的web题环境和pwn题环境，请自行更改相关文件。

## 演示

运行起来的web服务：

![](https://raw.githubusercontent.com/Yof3ng/images/master/img/20181103233718.png)

运行在同一docker容器内的pwn:

![](https://raw.githubusercontent.com/Yof3ng/images/master/img/20181103233932.png)

> 虽然非常简陋，但是用于练习还是足够的。



