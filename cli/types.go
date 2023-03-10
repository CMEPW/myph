package cli

type Options struct {

	// Shellcode path
	ShellcodePath string

	// Outfile path
	Outfile string

	// AES shellcode encryption secret
	AesKey []byte

	// os compilation target
	OS string

	// arch compilation target
	arch string

	// target process name to inject
	Target string
}
