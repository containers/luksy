package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/nalind/lukstool"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/unix"
)

var (
	checkPasswordFd = -1
)

func init() {
	checkpwCommand := &cobra.Command{
		Use:   "checkpw",
		Short: "Check a password for a LUKS-formatted file or device",
		RunE: func(cmd *cobra.Command, args []string) error {
			return checkpwCmd(cmd, args)
		},
		Args:    cobra.ExactArgs(1),
		Example: `lukstool checkpw /dev/mapper/encrypted-lv`,
	}

	flags := checkpwCommand.Flags()
	flags.SetInterspersed(false)
	flags.IntVar(&checkPasswordFd, "password-fd", -1, "read password from file descriptor")
	rootCmd.AddCommand(checkpwCommand)
}

func checkpwCmd(cmd *cobra.Command, args []string) error {
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	v1header, v2header, _, v2json, err := lukstool.ReadHeaders(f, lukstool.ReadHeaderOptions{})
	if err != nil {
		return err
	}
	var password string
	if checkPasswordFd != -1 {
		f := os.NewFile(uintptr(checkPasswordFd), fmt.Sprintf("FD %d", checkPasswordFd))
		passBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("reading from descriptor %d: %w", checkPasswordFd, err)
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
	switch {
	case v1header != nil:
		_, err = v1header.Check(password, f)
	case v2header != nil:
		_, err = v2header.Check(password, f, *v2json)
	default:
		err = errors.New("internal error: unknown format")
	}
	return err
}
