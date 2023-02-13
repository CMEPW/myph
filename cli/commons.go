package cli

import (
	"errors"
    "fmt"
    "os"

	"github.com/cmepw/myph/loader"
)

func LoadShellcode(opts *Options) (error, *loader.Shellcode) {
    if opts.ShellcodePath == "" {
        return errors.New("[!] No shellcode specified. Please use --shellcode"), nil
    }

    plaintext_payload, err := loader.ReadFile(opts.ShellcodePath); if err != nil {
        return err, nil
    }

    fmt.Println("[+] Successfully read shellcode")
    payload, err := loader.Encrypt(opts.AesKey, plaintext_payload); if err != nil {
        return err, nil
    }

    fmt.Println("[+] Encrypted shellcode with AES key")
    os.Setenv("GOOS", opts.OS)
    os.Setenv("GOARCH", opts.arch)
    s := &loader.Shellcode{
        Payload:  payload,
        Filename: opts.Outfile,
        AesKey:   []byte(opts.AesKey),
        Target:   opts.Target,
    }

    return nil, s
}
