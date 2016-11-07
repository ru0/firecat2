# firecat2


>内网渗透（建立数据转发隧道）必备神器，没有之一。firecat2 移除了反弹shell代码，仅保留了转发tunnel功能。


##编译环境

Microsoft Visual Studio Professional 2012
版本 11.0.61219.00 Update 5
Microsoft .NET Framework
版本 4.5.51641

##OS 
Microsoft Windows Embedded 8.1 Industry Pro
6.3.9600 暂缺 Build 9600


>gcc -o firecat.exe firecat.c -lwsock32


##注意几个地方
* 1，配置属性-常规 字符集  使用多字节字符集 unicode会找不到cmd.exe路径
* 2，C/C++ -常规   附加包含目录 配置问include头文件目录
* 3，连接器-常规   附加库目录 配置为lib库文件目录
* 4，配置属性-常规 平台工具集 vs-xp
* 5，调试时, 在监视1窗口(Watch 1)中输入 $err,hr 获取GetLastError()
