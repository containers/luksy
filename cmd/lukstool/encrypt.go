package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/nalind/lukstool"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/unix"
)

var (
	encryptPasswordFd   = -1
	encryptPasswordFile = ""
	encryptv1           = false
)

func init() {
	encryptCommand := &cobra.Command{
		Use:   "encrypt",
		Short: "Create a LUKS-formatted file or device",
		RunE: func(cmd *cobra.Command, args []string) error {
			return encryptCmd(cmd, args)
		},
		Args:    cobra.ExactArgs(2),
		Example: `lukstool encrypt /tmp/plaintext.img /tmp/encrypted.img`,
	}

	flags := encryptCommand.Flags()
	flags.SetInterspersed(false)
	flags.IntVar(&encryptPasswordFd, "password-fd", -1, "read password from file descriptor")
	flags.StringVar(&encryptPasswordFile, "password-file", "", "read password from file")
	flags.BoolVarP(&encryptv1, "luks1", "1", false, "create LUKSv1 instead of LUKSv2")
	rootCmd.AddCommand(encryptCommand)
}

func encryptCmd(cmd *cobra.Command, args []string) error {
	input, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("open %q: %w", args[0], err)
	}
	defer input.Close()
	st, err := input.Stat()
	if err != nil {
		return err
	}
	if st.Size()%lukstool.V1SectorSize != 0 {
		return fmt.Errorf("%q is not of a suitable size, expected a multiple of %d bytes", input.Name(), lukstool.V1SectorSize)
	}
	var password string
	if encryptPasswordFd != -1 {
		passFile := os.NewFile(uintptr(encryptPasswordFd), fmt.Sprintf("FD %d", encryptPasswordFd))
		passBytes, err := io.ReadAll(passFile)
		if err != nil {
			return fmt.Errorf("reading from descriptor %d: %w", encryptPasswordFd, err)
		}
		password = string(passBytes)
	} else if encryptPasswordFile != "" {
		passBytes, err := ioutil.ReadFile(encryptPasswordFile)
		if err != nil {
			return err
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
	var encryptStream func([]byte) ([]byte, error)
	if encryptv1 {
		header, encryptStream, err = lukstool.EncryptV1([]string{password})
		if err != nil {
			return fmt.Errorf("creating luksv1 data: %w", err)
		}
	} else {
		header, encryptStream, err = lukstool.EncryptV2([]string{password})
		if err != nil {
			return fmt.Errorf("creating luksv2 data: %w", err)
		}
	}
	output, err := os.Create(args[1])
	if err != nil {
		return fmt.Errorf("create %q: %w", args[1], err)
	}
	defer output.Close()
	n, err := output.Write(header)
	if err != nil {
		return err
	}
	if n != len(header) {
		return fmt.Errorf("short write while writing header to %q", output.Name())
	}
	buf := make([]byte, 1024*1024)
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for {
		n, err := input.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		encrypted, err := encryptStream(buf[:n])
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
		n, err = output.Write(encrypted)
		if err != nil {
			return err
		}
		if n != len(encrypted) {
			return fmt.Errorf("short write saving encrypted output: %d < %d", n, len(encrypted))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			break
		}
	}
	return err
}
