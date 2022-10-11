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
		Args:    cobra.RangeArgs(1, 2),
		Example: `lukstool checkpw /dev/mapper/encrypted-lv [plaintext.img]`,
	}

	flags := checkpwCommand.Flags()
	flags.SetInterspersed(false)
	flags.IntVar(&checkPasswordFd, "password-fd", -1, "read password from file descriptor")
	rootCmd.AddCommand(checkpwCommand)
}

func checkpwCmd(cmd *cobra.Command, args []string) error {
	input, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer input.Close()
	v1header, v2header, v2header2, v2json, err := lukstool.ReadHeaders(input, lukstool.ReadHeaderOptions{})
	if err != nil {
		return err
	}
	if v2header != nil && v2header2 != nil && v2header2.SequenceID() > v2header.SequenceID() {
		v2header, v2header2 = v2header2, v2header
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
	var decryptStream func([]byte) ([]byte, error)
	var payloadOffset, payloadSize int64
	switch {
	case v1header != nil:
		decryptStream, payloadOffset, payloadSize, err = v1header.Check(password, input)
	case v2header != nil:
		decryptStream, payloadOffset, payloadSize, err = v2header.Check(password, input, *v2json)
	default:
		err = errors.New("internal error: unknown format")
	}
	if err == nil && len(args) >= 2 {
		output, err := os.Create(args[1])
		if err != nil {
			return err
		}
		defer output.Close()
		buf := make([]byte, 1024*1024)
		if _, err := input.Seek(payloadOffset, io.SeekStart); err != nil {
			return err
		}
		for payloadSize > 0 {
			want := payloadSize
			if want > int64(len(buf)) {
				want = int64(len(buf))
			}
			n, err := input.Read(buf[:want])
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if int64(n) != want {
				return fmt.Errorf("short read: wanted %d bytes, got %d bytes", want, n)
			}
			plaintext, err := decryptStream(buf[:want])
			if err != nil {
				return err
			}
			n, err = output.Write(plaintext[:want])
			if err != nil {
				return err
			}
			if int64(n) != want {
				return fmt.Errorf("short write: tried %d bytes, wrote %d bytes", want, n)
			}
			payloadSize -= int64(n)
		}
	}
	return err
}
