# PortScan
TCP port scanning tools

## 说明 
源码使用python编写，基于 raw_sockets(https://github.com/YingquanYuan/raw_sockets)修改而成 
代码可以进一步定制，本人只是在原来代码的基础上稍微修改了一下。

## 原理

利用TCP的三次握手完成端口确认，即发送一次syn包，如果有应答则认为端口存活


