package lukstool

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func CreateV1(password []string) ([]byte, []byte, error) {
	salt := make([]byte, v1SaltSize)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}
	if n != len(salt) {
		return nil, nil, errors.New("short read")
	}
	ksSalt := make([]byte, v1KeySlotSaltLength*8)
	n, err = rand.Read(ksSalt)
	if err != nil {
		return nil, nil, err
	}
	if n != len(ksSalt) {
		return nil, nil, errors.New("short read")
	}
	var h V1Header
	h.SetMagic(V1Magic)
	h.SetVersion(1)
	h.SetCipherName("aes")
	h.SetCipherMode("xts-plain64")
	h.SetHashSpec("sha256")
	h.SetKeyBytes(32)
	h.SetMKDigestSalt(salt)
	h.SetMKDigestIter(4000)
	h.SetUUID("")
	mkey := make([]byte, h.KeyBytes())
	n, err = rand.Read(mkey)
	if err != nil {
		return nil, nil, err
	}
	if n != len(mkey) {
		return nil, nil, errors.New("short read")
	}
	hasher, err := hasherByName(h.HashSpec())
	if err != nil {
		return nil, nil, errors.New("internal error")
	}
	mkdigest := pbkdf2.Key(mkey, h.MKDigestSalt(), int(h.MKDigestIter()), v1DigestSize, hasher)
	h.SetMKDigest(mkdigest)
	headerLength := roundUpToMultiple(v1HeaderStructSize, V1AlignKeyslots)
	var stripes [][]byte
	for i := 0; i < 7; i++ {
		var keyslot V1KeySlot
		keyslot.SetActive(i < len(password))
		keyslot.SetIterations(h.MKDigestIter())
		keyslot.SetStripes(h.MKDigestIter())
		keyslot.SetKeySlotSalt(ksSalt[i*v1KeySlotSaltLength : (i+1)*v1KeySlotSaltLength])
		if i < len(password) {
			splitKey, err := afSplit(mkey, hasher(), int(h.MKDigestIter()))
			if err != nil {
				return nil, nil, fmt.Errorf("splitting key: %w", err)
			}
			striped, err := v1encrypt(h.CipherName(), h.CipherMode(), mkey, splitKey)
			if err != nil {
				return nil, nil, fmt.Errorf("encrypting split key with password: %w", err)
			}
			stripes = append(stripes, striped)
			if len(striped) != len(mkey)*int(keyslot.Stripes()) {
				return nil, nil, fmt.Errorf("internal error: got %d stripe bytes, expected %d", len(striped), len(mkey)*int(keyslot.Stripes()))
			}
		}
		keyslot.SetKeyMaterialOffset(uint32(headerLength / V1SectorSize))
		h.SetKeySlot(i, keyslot)
		headerLength += len(mkey) * int(keyslot.Stripes())
		headerLength = roundUpToMultiple(v1HeaderStructSize, V1AlignKeyslots)
	}
	return nil, nil, nil
}

func CreateV2(password []string) ([]byte, []byte, error) {
	salt := make([]byte, v2SaltLength)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, nil, err
	}
	if n != len(salt) {
		return nil, nil, errors.New("short read")
	}

	var h1, h2 V2Header
	h1.SetMagic(V2Magic1)
	h2.SetMagic(V2Magic2)
	h1.SetVersion(2)
	h2.SetVersion(2)
	h1.SetSequenceID(1)
	h2.SetSequenceID(1)
	h1.SetLabel("")
	h2.SetLabel("")
	h1.SetChecksumAlgorithm("sha256")
	h2.SetChecksumAlgorithm("sha256")
	h1.SetSalt(salt)
	h2.SetSalt(salt)
	h1.SetUUID("")
	h2.SetUUID("")
	h1.SetHeaderOffset(0)
	h2.SetHeaderOffset(0)
	h1.SetChecksum([]byte{})
	h2.SetChecksum([]byte{})
	return nil, nil, nil
}
