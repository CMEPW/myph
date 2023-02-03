package cli

// Get default value for Options struct
func GetDefaultCLIOptions() Options {
    opts := Options{
        ShellcodePath: "",
        AesKey: "VerySecretAESKey",
        Outfile: "myph-out",
    }

    return opts
}