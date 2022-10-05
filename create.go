package lukstool

import (
	"crypto/rand"
	"errors"
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
	for i := 0; i < 7; i++ {
		var keyslot V1KeySlot
		keyslot.SetActive(i < len(password))
		keyslot.SetIterations(h.MKDigestIter())
		keyslot.SetStripes(4000)
		keyslot.SetKeySlotSalt(ksSalt[i*v1KeySlotSaltLength : (i+1)*v1KeySlotSaltLength])
		h.SetKeySlot(i, keyslot)
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
