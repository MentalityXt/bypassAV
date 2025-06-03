# 免责声明
此项目为开源项目，仅提供与学习。请勿用于违法行为，造成的违法行为与本人无关。

# 更新情况说明
// 开源项目loader特征极易被捕获，当前loader如果被常见AV其中之一(huorong,360,wd等等)查杀之后，会持续在Releases里更新loader，直到当前源码特征被完全捕获无法bypass，这个时候会更新新的源码以供参考。
// 感兴趣可以点个star持续关注！！

360捕获了静态特征，源码编译后会直接被静态查杀，针对其他AV依然可用，Releases已经更新，使用方法不变，直到特征被完全捕获。

## 20250603
20250601.exe静态特征已被360捕获，已经更新Releases最新loader 20250603.exe 

## ~~20250601~~
~~20250601也是基于源码生成，可以进行绕过360静态查杀。~~

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

# 用法
打开加密.py 将shellcode填进去加密会生成文件rundllogon.bin，和编译好的exe放一起就行
