package lukstool

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

func CreateV1(password []string) ([]byte, []byte, error) {
	if len(password) == 0 {
		return nil, nil, errors.New("at least one password is required")
	}
	if len(password) > v1NumKeys {
		return nil, nil, fmt.Errorf("attempted to use %d passwords, only %d possible", len(password), v1NumKeys)
	}

	salt := make([]byte, v1SaltSize)
	n, err := rand.Read(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("reading random data: %w", err)
	}
	if n != len(salt) {
		return nil, nil, errors.New("short read")
	}

	ksSalt := make([]byte, v1KeySlotSaltLength*8)
	n, err = rand.Read(ksSalt)
	if err != nil {
		return nil, nil, fmt.Errorf("reading random data: %w", err)
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
	h.SetKeyBytes(64)
	h.SetMKDigestSalt(salt)
	h.SetMKDigestIter(V1Stripes)
	h.SetUUID(uuid.NewString())

	mkey := make([]byte, h.KeyBytes())
	n, err = rand.Read(mkey)
	if err != nil {
		return nil, nil, fmt.Errorf("reading random data: %w", err)
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
	iterations := IterationsPBKDF2(salt, int(h.KeyBytes()), hasher)
	var stripes [][]byte
	for i := 0; i < v1NumKeys; i++ {
		var keyslot V1KeySlot
		keyslot.SetActive(i < len(password))
		keyslot.SetIterations(uint32(iterations))
		keyslot.SetStripes(V1Stripes)
		keyslot.SetKeySlotSalt(ksSalt[i*v1KeySlotSaltLength : (i+1)*v1KeySlotSaltLength])
		if i < len(password) {
			splitKey, err := afSplit(mkey, hasher(), int(h.MKDigestIter()))
			if err != nil {
				return nil, nil, fmt.Errorf("splitting key: %w", err)
			}
			passwordDerived := pbkdf2.Key([]byte(password[i]), keyslot.KeySlotSalt(), int(keyslot.Iterations()), int(h.KeyBytes()), hasher)
			striped, err := v1encrypt(h.CipherName(), h.CipherMode(), passwordDerived, splitKey)
			if err != nil {
				return nil, nil, fmt.Errorf("encrypting split key with password: %w", err)
			}
			if len(striped) != len(mkey)*int(keyslot.Stripes()) {
				return nil, nil, fmt.Errorf("internal error: got %d stripe bytes, expected %d", len(striped), len(mkey)*int(keyslot.Stripes()))
			}
			stripes = append(stripes, striped)
		}
		keyslot.SetKeyMaterialOffset(uint32(headerLength / V1SectorSize))
		h.SetKeySlot(i, keyslot)
		headerLength += len(mkey) * int(keyslot.Stripes())
		headerLength = roundUpToMultiple(headerLength, V1AlignKeyslots)
	}
	headerLength = roundUpToMultiple(headerLength, V1SectorSize)

	h.SetPayloadOffset(uint32(headerLength / V1SectorSize))
	head := make([]byte, headerLength)
	offset := copy(head, h[:])
	offset = roundUpToMultiple(offset, V1AlignKeyslots)
	for _, stripe := range stripes {
		copy(head[offset:], stripe)
		offset = roundUpToMultiple(offset, V1AlignKeyslots)
	}
	return head, mkey, nil
}

func CreateV2(password []string) ([]byte, []byte, error) {
	if len(password) == 0 {
		return nil, nil, errors.New("at least one password is required")
	}
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
	uuidString := uuid.NewString()
	h1.SetUUID(uuidString)
	h2.SetUUID(uuidString)
	h1.SetHeaderOffset(0)
	h2.SetHeaderOffset(0)
	h1.SetChecksum([]byte{})
	h2.SetChecksum([]byte{})

	mkey := make([]byte, 64)
	n, err = rand.Read(mkey)
	if err != nil {
		return nil, nil, fmt.Errorf("reading random data: %w", err)
	}
	if n != len(mkey) {
		return nil, nil, errors.New("short read")
	}

	hasher, err := hasherByName(h1.ChecksumAlgorithm())
	if err != nil {
		return nil, nil, errors.New("internal error")
	}
	iterations := IterationsPBKDF2(salt, len(mkey), hasher)

	mdigest := pbkdf2.Key(mkey, salt, iterations, len(hasher().Sum([]byte{})), hasher)
	digest0 := V2JSONDigest{
		Type:   "pbkdf2",
		Salt:   salt,
		Digest: mdigest,
		V2JSONDigestPbkdf2: &V2JSONDigestPbkdf2{
			Hash:       h1.ChecksumAlgorithm(),
			Iterations: iterations,
		},
	}

	j := V2JSON{
		Config: V2JSONConfig{
			JsonSize:     0,
			KeyslotsSize: 0,
		},
		Keyslots: map[string]V2JSONKeyslot{},
		Digests: map[string]V2JSONDigest{
			"0": digest0,
		},
		Segments: map[string]V2JSONSegment{},
		Tokens:   map[string]V2JSONToken{},
	}

	keyslotSalt := make([]byte, 64)
	timeCost := 1
	threadsCost := 4
	memoryCost := MemoryCostArgon2(keyslotSalt, len(mkey), timeCost, threadsCost)
	priority := V2JSONKeyslotPriorityNormal
	var stripes [][]byte
	for i := range password {
		n, err := rand.Read(keyslotSalt)
		if err != nil {
			return nil, nil, err
		}
		if n != len(salt) {
			return nil, nil, errors.New("short read")
		}
		key := argon2.Key([]byte(password[i]), keyslotSalt, uint32(timeCost), uint32(memoryCost), uint8(threadsCost), uint32(len(mkey)))
		split, err := afSplit(key, hasher(), V2Stripes)
		if err != nil {
			return nil, nil, fmt.Errorf("splitting: %w", err)
		}
		striped, err := v2encrypt("aes-xts-plain64", key, split)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypting: %w", err)
		}
		stripes = append(stripes, striped)
		keyslot := V2JSONKeyslot{
			Type:    "luks2",
			KeySize: len(mkey),
			Area: V2JSONArea{
				Type:   "raw",
				Offset: 1, // update
				Size:   int64(len(striped)),
				V2JSONAreaRaw: &V2JSONAreaRaw{
					Encryption: "aes-xts-plain64",
					KeySize:    len(key),
				},
			},
			Priority: &priority,
			V2JSONKeyslotLUKS2: &V2JSONKeyslotLUKS2{
				AF: V2JSONAF{
					Type: "luks1",
					V2JSONAFLUKS1: &V2JSONAFLUKS1{
						Stripes: V2Stripes,
						Hash:    h1.ChecksumAlgorithm(),
					},
				},
				Kdf: V2JSONKdf{
					Type: "argon2i",
					Salt: keyslotSalt,
					V2JSONKdfArgon2i: &V2JSONKdfArgon2i{
						Time:   timeCost,
						Memory: memoryCost,
						CPUs:   threadsCost,
					},
				},
			},
		}
		j.Keyslots[fmt.Sprintf("%d", i)] = keyslot
	}

	j.Segments["0"] = V2JSONSegment{
		Type:   "crypt",
		Offset: "1", // FIXME
		Size:   "dynamic",
		V2JSONSegmentCrypt: &V2JSONSegmentCrypt{
			IVTweak:    0,
			Encryption: "aes-xts-plain64",
			SectorSize: V1SectorSize,
		},
	}

	var encoded []byte
	encoded, err = json.Marshal(j)
	if err != nil {
		return nil, nil, err
	}
	for j.Config.JsonSize != len(encoded) {
		j.Config.JsonSize = len(encoded)
		encoded, err = json.Marshal(j)
		if err != nil {
			return nil, nil, err
		}
	}

	return nil, nil, nil
}
