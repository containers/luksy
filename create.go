package lukstool

import (
	"crypto/rand"
	"errors"
)

func CreateV1() ([]byte, error) {
	salt := make([]byte, V1SaltSize)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	if n != len(salt) {
		return nil, errors.New("short read")
	}
	ksSalt := make([]byte, v1KeySlotSaltLength*8)
	n, err = rand.Read(ksSalt)
	if err != nil {
		return nil, err
	}
	if n != len(ksSalt) {
		return nil, errors.New("short read")
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
		keyslot.SetActive(false)
		keyslot.SetIterations(h.MKDigestIter())
		keyslot.SetStripes(4000)
		keyslot.SetKeySlotSalt(ksSalt[i*v1KeySlotSaltLength : (i+1)*v1KeySlotSaltLength])
		h.SetKeySlot(i, keyslot)
	}
	return nil, nil
}
