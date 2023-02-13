package loader

import (
	"fmt"
	"os"
	"os/exec"
)

func Compile(sc Shellcode) {
    fmt.Println("[+] Disabling telemetry")
    err := exec.Command(
		"go",
        "env",
        "-w",
        "GOTELEMETRY=off",
        ).Run()
	if err != nil {
		println("[!] go env error: " + err.Error())
		os.Exit(1)
	}

	err = exec.Command(
		"go",
		"build",
		"-ldflags",
		"-s -w -H=windowsgui",
		"-o",
		sc.Filename,
		"tmp.go",
	).Run()
	if err != nil {
		println("[!] Compile error: " + err.Error())
		os.Exit(1)
	}
	fmt.Println("[+] Successfully compiled shellcode")
	os.Remove("tmp.go")

}
