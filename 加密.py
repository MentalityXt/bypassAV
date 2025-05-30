from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY = bytes.fromhex("B0498CB50D520D7707E5CE310D1F1C85")  
IV = bytes.fromhex("AFA4DFAAB88719F5483145AC835DC5D5")  

shellcode = b""
cipher = AES.new(KEY, AES.MODE_CBC, IV)

padded_shellcode = pad(shellcode, AES.block_size)

ciphertext = cipher.encrypt(padded_shellcode)

with open("rundllogon.bin", "wb") as f:
    f.write(ciphertext)

print("Shellcode 加密完成，保存到 rundllogon.bin")
