package main

import (
	"fmt"
	"io"
	"os"

	"github.com/nalind/lukstool"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/unix"
)

var (
	createPasswordFd = -1
	createv1         = false
)

func init() {
	createCommand := &cobra.Command{
		Use:   "create",
		Short: "Create a LUKS-formatted file or device",
		RunE: func(cmd *cobra.Command, args []string) error {
			return createCmd(cmd, args)
		},
		Args:    cobra.ExactArgs(2),
		Example: `lukstool create /dev/mapper/plaintext-lv /tmp/encrypted.img`,
	}

	flags := createCommand.Flags()
	flags.SetInterspersed(false)
	flags.IntVar(&createPasswordFd, "password-fd", -1, "read password from file descriptor")
	flags.BoolVarP(&createv1, "luks1", "1", false, "create LUKSv1 instead of LUKSv2")
	rootCmd.AddCommand(createCommand)
}

func createCmd(cmd *cobra.Command, args []string) error {
	f, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("open %q: %w", args[0], err)
	}
	defer f.Close()
	var password string
	if createPasswordFd != -1 {
		passFile := os.NewFile(uintptr(createPasswordFd), fmt.Sprintf("FD %d", createPasswordFd))
		passBytes, err := io.ReadAll(passFile)
		if err != nil {
			return fmt.Errorf("reading from descriptor %d: %w", createPasswordFd, err)
		}
		password = string(passBytes)
	} else {
		if terminal.IsTerminal(unix.Stdin) {
			fmt.Fprintf(os.Stdout, "Password: ")
			os.Stdout.Sync()
			passBytes, err := terminal.ReadPassword(unix.Stdin)
			if err != nil {
				return fmt.Errorf("reading from stdin: %w", err)
			}
			password = string(passBytes)
			fmt.Fprintln(os.Stdout)
		} else {
			passBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading from stdin: %w", err)
			}
			password = string(passBytes)
		}
	}
	var header []byte
	if createv1 {
		header, _, err = lukstool.CreateV1([]string{password})
		if err != nil {
			return fmt.Errorf("creating luksv1 data: %w", err)
		}
	} else {
		header, _, err = lukstool.CreateV2([]string{password})
		if err != nil {
			return fmt.Errorf("creating luksv2 data: %w", err)
		}
	}
	f, err = os.Create(args[1])
	if err != nil {
		return fmt.Errorf("create %q: %w", args[1], err)
	}
	defer f.Close()
	n, err := f.Write(header)
	if err != nil {
		return err
	}
	if n != len(header) {
		return fmt.Errorf("short write while writing header to %q", f.Name())
	}
	return err
}
