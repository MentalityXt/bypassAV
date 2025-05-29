# bypassAV
分离免杀shellcodeloader 20250529有效 VT 2/71
![image](https://github.com/user-attachments/assets/e7023bcd-1cbf-449f-b4e7-0a24d6f338cb)

静态火绒360卡巴wd都可以过
动态WD需要将beacon.dll带入到shellcode当中
![image](https://github.com/user-attachments/assets/38bcd517-5b49-41c2-9d8a-207b1fc1acdd)

不然在通信过程中始终会被wd动态拦截

![image](https://github.com/user-attachments/assets/64d51dfb-a256-47af-b3a6-245cfb9fc8e6)
![image](https://github.com/user-attachments/assets/d634e2f1-118a-44b4-b526-e16d119a58be)

这个项目不是很成熟 欠缺很多，比如反沙箱 反调试 延迟执行这些都没有做，需要的可以自己加或者去其他开源的免杀项目上copy一份加进去都行
不定期更新
# 用法
打开加密.py 将shellcode填进去加密会生成文件rundllogon.bin，和编译好的exe放一起就行
