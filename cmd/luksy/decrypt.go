package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containers/luksy"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	decryptPasswordFd   = -1
	decryptPasswordFile = ""
	decryptForce        = false
)

func init() {
	decryptCommand := &cobra.Command{
		Use:   "decrypt",
		Short: "Check a password for a LUKS-formatted file or device, and decrypt it",
		RunE: func(cmd *cobra.Command, args []string) error {
			return decryptCmd(cmd, args)
		},
		Args:    cobra.RangeArgs(1, 2),
		Example: `luksy decrypt /dev/mapper/encrypted-lv [plaintext.img]`,
	}

	flags := decryptCommand.Flags()
	flags.SetInterspersed(false)
	flags.IntVar(&decryptPasswordFd, "password-fd", -1, "read password from file descriptor")
	flags.StringVar(&decryptPasswordFile, "password-file", "", "read password from file")
	flags.BoolVarP(&decryptForce, "force-overwrite", "f", false, "forcibly overwrite existing output files")
	rootCmd.AddCommand(decryptCommand)
}

func decryptCmd(cmd *cobra.Command, args []string) error {
	if len(args) >= 2 {
		_, err := os.Stat(args[1])
		if (err == nil || !os.IsNotExist(err)) && !decryptForce {
			if err != nil {
				return fmt.Errorf("checking if %q exists: %w", args[1], err)
			}
			return fmt.Errorf("-f not specified, and %q exists", args[1])
		}
	}
	input, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer input.Close()
	v1header, v2header, v2header2, v2json, err := luksy.ReadHeaders(input, luksy.ReadHeaderOptions{})
	if err != nil {
		return err
	}
	if v2header != nil && v2header2 != nil && v2header2.SequenceID() > v2header.SequenceID() {
		v2header = v2header2
	}
	var password string
	if decryptPasswordFd != -1 {
		f := os.NewFile(uintptr(decryptPasswordFd), fmt.Sprintf("FD %d", decryptPasswordFd))
		passBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("reading from descriptor %d: %w", decryptPasswordFd, err)
		}
		password = string(passBytes)
	} else if decryptPasswordFile != "" {
		passBytes, err := os.ReadFile(decryptPasswordFile)
		if err != nil {
			return err
		}
		password = string(passBytes)
	} else {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintf(os.Stdout, "Password: ")
			os.Stdout.Sync()
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
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
	password = strings.TrimRightFunc(password, func(r rune) bool { return r == '\r' || r == '\n' })
	var decryptStream func([]byte) ([]byte, error)
	var payloadOffset, payloadSize int64
	var decryptSectorSize int
	switch {
	case v1header != nil:
		decryptStream, decryptSectorSize, payloadOffset, payloadSize, err = v1header.Decrypt(password, input)
	case v2header != nil:
		decryptStream, decryptSectorSize, payloadOffset, payloadSize, err = v2header.Decrypt(password, input, *v2json)
	default:
		err = errors.New("internal error: unknown format")
	}
	if err == nil && len(args) >= 2 {
		var output *os.File
		output, err = os.Create(args[1])
		if err != nil {
			return err
		}
		defer output.Close()
		_, err = input.Seek(payloadOffset, io.SeekStart)
		if err != nil {
			return err
		}
		rc := luksy.DecryptReader(decryptStream, input, decryptSectorSize)
		defer rc.Close()
		reader := io.Reader(rc)
		if payloadSize >= 0 {
			reader = io.LimitReader(reader, payloadSize)
		}
		_, err = io.Copy(output, reader)
	}
	return err
}
