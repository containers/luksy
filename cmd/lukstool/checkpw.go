package main

import (
	"errors"
	"os"

	"github.com/nalind/lukstool"
	"github.com/spf13/cobra"
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
	switch {
	case v1header != nil:
		_, err = v1header.Check("password", f)
	case v2header != nil:
		_, err = v2header.Check("password", f, *v2json)
	default:
		err = errors.New("internal error: unknown format")
	}
	return err
}
