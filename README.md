# 免责声明
此项目为开源项目，仅提供与学习。请勿用于违法行为，造成的违法行为与本人无关。

# 更新情况说明
// 开源免杀项目特征极易被捕获，当前loader如果被常见AV其中之一查杀之后，会在Releases里更新可用loader，直到当前源码特征被完全捕获无法bypass，这个时候会更新新的源码以供参考。

// 感兴趣可以点个star持续关注！！

**一定要注意：源码已经开源，使用之前加几个cout或者随便加点啥都可以，建议虚拟机编译**，后续会开成自动化的

### 20250609
Releases已经更新20250608 shellcodeloader依然可用 **同时源码已经更新**

# 用法
```python
python encrypt.py -h
usage: encrypt.py [-h] [-r] [-o OUTPUT] [-i INPUT]

AES加密工具 - 支持随机密钥生成和文件输入

optional arguments:
  -h, --help            show this help message and exit
  -r, --random          使用随机生成的密钥和IV
  -o OUTPUT, --output OUTPUT
                        指定输出文件名 (默认: rundllUpdata.bin)
  -i INPUT, --input INPUT
                        包含shellcode的输入文件
```

### 参数-r会生成随机的密钥 根据生成的随机密钥去修改C++文件中的密钥(不加该参数--默认密钥和IV就是C++文件当中的可直接使用)

例如：

![image](https://github.com/user-attachments/assets/26ba561b-cd51-4622-9272-989fa35430c0)

### 参数-i后面需要指定文件 比如从cs中生成的shellcode(不加该参数生成的shellcode默认为x64的calc)

例如：

![image](https://github.com/user-attachments/assets/a193a70a-6560-4a8c-a124-45763ce65b43)

### 参数-o后面需要指定输出的文件名(默认输出为rundllUpdata.bin 需要在C++文件头部OUTPUT_FILE改成对应的)

例如：

![image](https://github.com/user-attachments/assets/10f0ab52-511a-47b5-95cf-ee76da8da55d)

参数可以多选单选和不选，根据情况来做测试。

# bypassAV
分离免杀shellcodeloader 20250529有效 VT 2/71

![image](https://github.com/user-attachments/assets/e7023bcd-1cbf-449f-b4e7-0a24d6f338cb)

静态火绒360卡巴wd都可以过

动态免杀WD需要将beacon.dll带入到shellcode当中，不然在通信过程中始终会被wd拦截，一般2-3个包请求到beacon.dll加载的时候直接报毒，可以自己抓包研究一下

动态免杀WD文件大了点但必须用下面这个code才能过，其他AV正常的code就可以过

![image](https://github.com/user-attachments/assets/38bcd517-5b49-41c2-9d8a-207b1fc1acdd)


360动态
![image](https://github.com/user-attachments/assets/64d51dfb-a256-47af-b3a6-245cfb9fc8e6)

WD动态
![image](https://github.com/user-attachments/assets/d634e2f1-118a-44b4-b526-e16d119a58be)

这个项目不是很成熟 欠缺很多，比如反沙箱 反调试 延迟执行这些都没有做，需要的可以自己加或者去其他开源的免杀项目上copy一份加进去都行

