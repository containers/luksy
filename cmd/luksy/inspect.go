package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/containers/luksy"
	"github.com/spf13/cobra"
)

var all bool

func init() {
	inspectCommand := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a LUKS-formatted file or device",
		RunE: func(cmd *cobra.Command, args []string) error {
			return inspectCmd(cmd, args)
		},
		Args:    cobra.ExactArgs(1),
		Example: `luksy - inspect /dev/mapper/encrypted-lv`,
	}

	flags := inspectCommand.Flags()
	flags.SetInterspersed(false)
	flags.BoolVarP(&all, "all", "a", false, "include information about inactive key slots")
	rootCmd.AddCommand(inspectCommand)
}

func inspectCmd(cmd *cobra.Command, args []string) error {
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	v1header, v2header, _, v2json, err := luksy.ReadHeaders(f, luksy.ReadHeaderOptions{})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
	defer tw.Flush()
	if v1header != nil {
		if v1header.Version() != 1 {
			return fmt.Errorf("internal error: magic/version mismatch (%d)", v1header.Version())
		}
		fmt.Fprintf(tw, "Magic\t%q\n", v1header.Magic())
		fmt.Fprintf(tw, "Version\t%d\n", v1header.Version())
		fmt.Fprintf(tw, "Cipher\t%s, %s\n", v1header.CipherName(), v1header.CipherMode())
		fmt.Fprintf(tw, "Hash\t%s\n", v1header.HashSpec())
		fmt.Fprintf(tw, "Payload offset sectors\t%d\n", v1header.PayloadOffset())
		fmt.Fprintf(tw, "Main key\tlength %d\n", v1header.KeyBytes())
		fmt.Fprintf(tw, "\tdigest %q\n", v1header.MKDigest())
		fmt.Fprintf(tw, "\tsalt %q\n", v1header.MKDigestSalt())
		fmt.Fprintf(tw, "\t%d rounds\n", v1header.MKDigestIter())
		fmt.Fprintf(tw, "UUID\t%s\n", v1header.UUID())
		for i := 0; i < 8; i++ {
			ks, err := v1header.KeySlot(i)
			if err != nil {
				return fmt.Errorf("reading key slot %d: %w", i, err)
			}
			active, err := ks.Active()
			if err != nil {
				return fmt.Errorf("reading key slot %d status: %w", i, err)
			}
			if active || all {
				active, err := ks.Active()
				activeStr := fmt.Sprintf("%t", active)
				if err != nil {
					activeStr = fmt.Sprintf("unknown (corrupted?): %v", err)
				}
				fmt.Fprintf(tw, "Slot %d\tactive\t%s\n", i, activeStr)
				fmt.Fprintf(tw, "\titerations\t%d\n", ks.Iterations())
				fmt.Fprintf(tw, "\tsalt\t%q\n", ks.KeySlotSalt())
				fmt.Fprintf(tw, "\tkey material offset sectors\t%d\n", ks.KeyMaterialOffset())
				fmt.Fprintf(tw, "\tstripes\t%d\n", ks.Stripes())
			}
		}
	}
	if v2header != nil {
		if v2header.Version() != 2 {
			return fmt.Errorf("internal error: magic/version mismatch (%d)", v2header.Version())
		}
		fmt.Fprintf(tw, "Magic\t%q\n", v2header.Magic())
		fmt.Fprintf(tw, "Version\t%d\n", v2header.Version())
		fmt.Fprintf(tw, "Header size\t%d\n", v2header.HeaderSize())
		fmt.Fprintf(tw, "Header offset\t%d\n", v2header.HeaderOffset())
		fmt.Fprintf(tw, "Checksum\t%q, algorithm %q\n", v2header.Checksum(), v2header.ChecksumAlgorithm())
		fmt.Fprintf(tw, "UUID\t%s\n", v2header.UUID())
		fmt.Fprintf(tw, "Requirements\t%v\n", v2json.Config.Requirements)
		for key, segment := range v2json.Segments {
			fmt.Fprintf(tw, "Segment %s\ttype %q, offset %s, size %s, flags %v\n", key, segment.Type, segment.Offset, segment.Size, segment.Flags)
			switch segment.Type {
			case "crypt":
				fmt.Fprintf(tw, "\tcrypt encryption %s, sector size %d, IV tweak %d\n", segment.Encryption, segment.SectorSize, segment.IVTweak)
				if segment.Integrity != nil {
					fmt.Fprintf(tw, "\tcrypt integrity type %s, journal encryption %s, journal integrity %s\n", segment.Integrity.Type, segment.Integrity.JournalEncryption, segment.Integrity.JournalIntegrity)
				}
			}
		}
		for key, slot := range v2json.Keyslots {
			fmt.Fprintf(tw, "Slot %s \ttype %s\n", key, slot.Type)
			switch slot.Type {
			case "luks2":
				fmt.Fprintf(tw, "\tluks2 AF type %s\n", slot.AF.Type)
				switch slot.AF.Type {
				case "luks1":
					fmt.Fprintf(tw, "\tluks1 AF stripes %d, hash %s\n", slot.AF.Stripes, slot.AF.Hash)
				}
				fmt.Fprintf(tw, "\tluks2 KDF type %s, salt %q\n", slot.Kdf.Type, slot.Kdf.Salt)
				switch slot.Kdf.Type {
				case "argon2i":
					fmt.Fprintf(tw, "\targon2i time %d, memory %d, cpus %d\n", slot.Kdf.Time, slot.Kdf.Memory, slot.Kdf.CPUs)
				case "pbkdf2":
					fmt.Fprintf(tw, "\tpbkdf2 hash %s, iterations %d\n", slot.Kdf.Hash, slot.Kdf.Iterations)
				}
			case "reencrypt":
				fmt.Fprintf(tw, "\treencrypt mode %s, direction %s\n", slot.Mode, slot.Direction)
			}
			fmt.Fprintf(tw, "\tarea type %q, offset %d, size %d\n", slot.Area.Type, slot.Area.Offset, slot.Area.Size)
			switch slot.Area.Type {
			case "raw":
				fmt.Fprintf(tw, "\traw encryption %q, key size %d\n", slot.Area.Encryption, slot.Area.KeySize)
			case "checksum":
				fmt.Fprintf(tw, "\tchecksum hash %q, sector size %d\n", slot.Area.Hash, slot.Area.SectorSize)
			case "datashift":
				fmt.Fprintf(tw, "\tdatashift shift size %d\n", slot.Area.ShiftSize)
			case "datashift-checksum":
				fmt.Fprintf(tw, "\tdatashift-checksum hash %q, sector size %d, shift size %d\n", slot.Area.Hash, slot.Area.SectorSize, slot.Area.ShiftSize)
			}
			if slot.Priority != nil {
				fmt.Fprintf(tw, "\tpriority %s\n", slot.Priority.String())
			}
		}
		for key, digest := range v2json.Digests {
			fmt.Fprintf(tw, "Digest %s\tdigest %q\n", key, digest.Digest)
			fmt.Fprintf(tw, "\tsalt\t%q\n", digest.Salt)
			fmt.Fprintf(tw, "\ttype\t%q\n", digest.Type)
			fmt.Fprintf(tw, "\tsegments\t%v\n", digest.Segments)
			switch digest.Type {
			case "pbkdf2":
				fmt.Fprintf(tw, "\thash %s, iterations %d\n", digest.Hash, digest.Iterations)
			}
		}
		for key, token := range v2json.Tokens {
			fmt.Fprintf(tw, "Token %s\ttype %s, keyslots %v\n", key, token.Type, token.Keyslots)
			switch token.Type {
			case "luks2-keyring":
				fmt.Fprintf(tw, "\tdescription %q\n", token.KeyDescription)
			}
		}
	}
	return nil
}
