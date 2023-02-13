package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/cmepw/myph/loader"
	"github.com/spf13/cobra"
)

func GetParser(opts *Options) *cobra.Command {
    version := "0.0.2"
    var crt = &cobra.Command{
        Use:                "crt",
        Version:            version,
        DisableSuggestions: true,
        Short:              "AV bypass shellcode creation framework",
        Long:               `Encodes to binary using CreateRemoteThread`,
        Run: func(cmd *cobra.Command, args []string) {

            err, s := LoadShellcode(opts); if err != nil {
                fmt.Printf("Could not load shellcode: %s\n", err.Error())
                os.Exit(1)
            }

            if strings.ToLower(opts.arch) != "windows" {
                fmt.Printf("[!] CRT can only work with Windows")
                os.Exit(1)
            }

            toCompile := loader.LoadCRTTemplate(*s)
            err = loader.WriteToTempfile(toCompile)
            if err != nil {
                fmt.Printf("Write error: %s\n", err.Error())
                os.Exit(1)
            }

            fmt.Println("[+] loaded CRT Windows template")

            /* run compilation */
            loader.Compile(*s)
        },
    }

    var cmd = &cobra.Command{
        Use:                "myph",
        Version:            version,
        DisableSuggestions: true,
        Short:              "AV bypass shellcode creation framework",
        Long:               `Basic shellcode loader`,
        Run: func(cmd *cobra.Command, args []string) {

            err, s := LoadShellcode(opts); if err != nil {
                fmt.Printf("Could not load shellcode: %s\n", err.Error())
                os.Exit(1)
            }

            // TODO: call to LoadBasicTemplate(*s)
            toCompile := loader.LoadCRTTemplate(*s)
            err = loader.WriteToTempfile(toCompile)
            if err != nil {
                fmt.Printf("Write error: %s\n", err.Error())
                os.Exit(1)
            }

            fmt.Println("[+] loaded template")

            /* run compilation */
            loader.Compile(*s)
        },
    }


    defaults := GetDefaultCLIOptions()

    cmd.PersistentFlags().StringVarP(&opts.Outfile, "outfile", "f", defaults.Outfile, "output filepath")
    cmd.PersistentFlags().StringVarP(&opts.ShellcodePath, "shellcode", "s", defaults.ShellcodePath, "shellcode path")
    cmd.PersistentFlags().BytesHexVarP(&opts.AesKey, "aes-key", "a", defaults.AesKey, "AES key for shellcode encryption")
    cmd.PersistentFlags().StringVarP(&opts.arch, "arch", "r", defaults.arch, "architecture compilation target")
    cmd.PersistentFlags().StringVarP(&opts.OS, "os", "o", defaults.OS, "OS compilation target")
    cmd.PersistentFlags().StringVarP(&opts.Target, "target-process", "t", defaults.Target, "target for process injection")

    cmd.AddCommand(crt)

    return cmd
}
