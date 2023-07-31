package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containers/luksy"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	encryptPasswordFds   = []int{}
	encryptPasswordFiles = []string{}
	encryptSectorSize    = 0
	encryptCipher        = ""
	encryptv1            = false
	encryptForce         = false
)

func init() {
	encryptCommand := &cobra.Command{
		Use:   "encrypt",
		Short: "Create a LUKS-formatted file or device",
		RunE: func(cmd *cobra.Command, args []string) error {
			return encryptCmd(cmd, args)
		},
		Args:    cobra.ExactArgs(2),
		Example: `luksy - encrypt /tmp/plaintext.img /tmp/encrypted.img`,
	}

	flags := encryptCommand.Flags()
	flags.SetInterspersed(false)
	flags.IntSliceVar(&encryptPasswordFds, "password-fd", nil, "read password from file descriptor `number`s")
	flags.StringSliceVar(&encryptPasswordFiles, "password-file", nil, "read password from `file`s")
	flags.BoolVarP(&encryptv1, "luks1", "1", false, "create LUKSv1 instead of LUKSv2")
	flags.IntVar(&encryptSectorSize, "sector-size", 0, "sector size for LUKSv2")
	flags.StringVarP(&encryptCipher, "cipher", "c", "", "encryption algorithm")
	flags.BoolVarP(&encryptForce, "force-overwrite", "f", false, "forcibly overwrite existing output files")
	rootCmd.AddCommand(encryptCommand)
}

func encryptCmd(cmd *cobra.Command, args []string) error {
	_, err := os.Stat(args[1])
	if (err == nil || !os.IsNotExist(err)) && !encryptForce {
		if err != nil {
			return fmt.Errorf("checking if %q exists: %w", args[1], err)
		}
		return fmt.Errorf("-f not specified, and %q exists", args[1])
	}
	input, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("open %q: %w", args[0], err)
	}
	defer input.Close()
	st, err := input.Stat()
	if err != nil {
		return err
	}
	if st.Size()%luksy.V1SectorSize != 0 {
		return fmt.Errorf("%q is not of a suitable size, expected a multiple of %d bytes", input.Name(), luksy.V1SectorSize)
	}
	var passwords []string
	for _, encryptPasswordFd := range encryptPasswordFds {
		passFile := os.NewFile(uintptr(encryptPasswordFd), fmt.Sprintf("FD %d", encryptPasswordFd))
		passBytes, err := io.ReadAll(passFile)
		if err != nil {
			return fmt.Errorf("reading from descriptor %d: %w", encryptPasswordFd, err)
		}
		passwords = append(passwords, string(passBytes))
	}
	for _, encryptPasswordFile := range encryptPasswordFiles {
		passBytes, err := os.ReadFile(encryptPasswordFile)
		if err != nil {
			return err
		}
		passwords = append(passwords, string(passBytes))
	}
	if len(passwords) == 0 {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintf(os.Stdout, "Password: ")
			os.Stdout.Sync()
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return fmt.Errorf("reading from stdin: %w", err)
			}
			passwords = append(passwords, string(passBytes))
			fmt.Fprintln(os.Stdout)
		} else {
			passBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading from stdin: %w", err)
			}
			passwords = append(passwords, string(passBytes))
		}
	}
	for i := range passwords {
		passwords[i] = strings.TrimRightFunc(passwords[i], func(r rune) bool { return r == '\r' || r == '\n' })
	}
	var header []byte
	var encryptStream func([]byte) ([]byte, error)
	if encryptv1 {
		header, encryptStream, encryptSectorSize, err = luksy.EncryptV1(passwords, encryptCipher)
		if err != nil {
			return fmt.Errorf("creating luksv1 data: %w", err)
		}
	} else {
		header, encryptStream, encryptSectorSize, err = luksy.EncryptV2(passwords, encryptCipher, encryptSectorSize)
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
	wc := luksy.EncryptWriter(encryptStream, output, encryptSectorSize)
	defer wc.Close()
	_, err = io.Copy(wc, input)
	return err
}
