package lukstool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/xts"
)

func v1encrypt(cipherName, cipherMode string, key []byte, plaintext []byte) ([]byte, error) {
	var err error
	ciphertext := make([]byte, len(plaintext))
	switch cipherName {
	case "aes":
		switch cipherMode {
		case "ecb":
			cipher, err := aes.NewCipher(key)
			if err != nil {
				return nil, fmt.Errorf("initializing decryption: %w", err)
			}
			for processed := 0; processed < len(plaintext); processed += cipher.BlockSize() {
				blockLeft := V1SectorSize
				if processed+blockLeft > len(plaintext) {
					blockLeft = len(plaintext) - processed
				}
				cipher.Encrypt(ciphertext[processed:processed+blockLeft], plaintext[processed:processed+blockLeft])
			}
		case "cbc-plain":
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, fmt.Errorf("initializing decryption: %w", err)
			}
			for processed := 0; processed < len(plaintext); processed += V1SectorSize {
				blockLeft := V1SectorSize
				if processed+blockLeft > len(plaintext) {
					blockLeft = len(plaintext) - processed
				}
				ivValue := processed / V1SectorSize
				iv := []byte{uint8((ivValue) & 0xff), uint8((ivValue >> 8) & 0xff), uint8((ivValue >> 16) & 0xff), uint8((ivValue >> 24) & 0xff)}
				iv0 := make([]byte, aes.BlockSize)
				copy(iv0, iv)
				cipher := cipher.NewCBCEncrypter(block, iv0)
				cipher.CryptBlocks(ciphertext[processed:processed+blockLeft], plaintext[processed:processed+blockLeft])
			}
		case "xts-plain64":
			cipher, err := xts.NewCipher(aes.NewCipher, key)
			if err != nil {
				return nil, fmt.Errorf("initializing decryption: %w", err)
			}
			for processed := 0; processed < len(plaintext); processed += V1SectorSize {
				blockLeft := V1SectorSize
				if processed+blockLeft > len(plaintext) {
					blockLeft = len(plaintext) - processed
				}
				cipher.Encrypt(ciphertext[processed:processed+blockLeft], plaintext[processed:processed+blockLeft], uint64(processed/V1SectorSize))
			}
		default:
			return nil, fmt.Errorf("unsupported cipher mode %s", cipherMode)
		}
	default:
		return nil, fmt.Errorf("unsupported cipher %s", cipherName)
	}
	if err != nil {
		return nil, fmt.Errorf("cipher error: %w", err)
	}
	return ciphertext, nil
}

func v1decrypt(cipherName, cipherMode string, key []byte, ciphertext []byte) ([]byte, error) {
	var err error
	plaintext := make([]byte, len(ciphertext))
	switch cipherName {
	case "aes":
		switch cipherMode {
		case "ecb":
			cipher, err := aes.NewCipher(key)
			if err != nil {
				return nil, fmt.Errorf("initializing decryption: %w", err)
			}
			for processed := 0; processed < len(ciphertext); processed += cipher.BlockSize() {
				blockLeft := V1SectorSize
				if processed+blockLeft > len(ciphertext) {
					blockLeft = len(ciphertext) - processed
				}
				cipher.Decrypt(plaintext[processed:processed+blockLeft], ciphertext[processed:processed+blockLeft])
			}
		case "cbc-plain":
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, fmt.Errorf("initializing decryption: %w", err)
			}
			for processed := 0; processed < len(plaintext); processed += V1SectorSize {
				blockLeft := V1SectorSize
				if processed+blockLeft > len(plaintext) {
					blockLeft = len(plaintext) - processed
				}
				ivValue := processed / V1SectorSize
				iv := []byte{uint8((ivValue) & 0xff), uint8((ivValue >> 8) & 0xff), uint8((ivValue >> 16) & 0xff), uint8((ivValue >> 24) & 0xff)}
				iv0 := make([]byte, aes.BlockSize)
				copy(iv0, iv)
				cipher := cipher.NewCBCDecrypter(block, iv0)
				cipher.CryptBlocks(plaintext[processed:processed+blockLeft], ciphertext[processed:processed+blockLeft])
			}
		case "xts-plain64":
			cipher, err := xts.NewCipher(aes.NewCipher, key)
			if err != nil {
				return nil, fmt.Errorf("initializing decryption: %w", err)
			}
			for processed := 0; processed < len(ciphertext); processed += V1SectorSize {
				blockLeft := V1SectorSize
				if processed+blockLeft > len(ciphertext) {
					blockLeft = len(ciphertext) - processed
				}
				cipher.Decrypt(plaintext[processed:processed+blockLeft], ciphertext[processed:processed+blockLeft], uint64(processed/V1SectorSize))
			}
		default:
			return nil, fmt.Errorf("unsupported cipher mode %s", cipherMode)
		}
	default:
		return nil, fmt.Errorf("unsupported cipher %s", cipherName)
	}
	if err != nil {
		return nil, fmt.Errorf("cipher error: %w", err)
	}
	return plaintext, nil
}

func v2decrypt(cipherSuite string, key []byte, ciphertext []byte) ([]byte, error) {
	var cipherName, cipherMode string
	switch {
	case strings.HasPrefix(cipherSuite, "aes-"):
		cipherName = "aes"
		cipherMode = strings.TrimPrefix(cipherSuite, "aes-")
	default:
		cipherSpec := strings.SplitN(cipherSuite, "-", 2)
		if len(cipherSpec) < 2 {
			return nil, fmt.Errorf("unrecognized cipher suite %q", cipherSuite)
		}
		cipherName = cipherSpec[0]
		cipherMode = cipherSpec[1]
	}
	return v1decrypt(cipherName, cipherMode, key, ciphertext)
}

func diffuse(key []byte, h hash.Hash) []byte {
	sum := make([]byte, len(key))
	counter := 0
	for summed := 0; summed < len(key); summed += h.Size() {
		h.Reset()
		h.Write([]byte{uint8((counter >> 24) & 0xff), uint8((counter >> 16) & 0xff), uint8((counter >> 8) & 0xff), uint8((counter) & 0xff)})
		needed := len(key) - summed
		if needed > h.Size() {
			needed = h.Size()
		}
		h.Write(key[summed : summed+needed])
		partial := h.Sum(nil)
		copy(sum[summed:summed+needed], partial)
		counter++
	}
	return sum
}

func afMerge(splitKey []byte, h hash.Hash, keysize int, stripes int) ([]byte, error) {
	if len(splitKey) != keysize*stripes {
		return nil, fmt.Errorf("expected %d af bytes, got %d", keysize*stripes, len(splitKey))
	}
	d := make([]byte, keysize)
	for i := 0; i < stripes-1; i++ {
		for j := 0; j < keysize; j++ {
			d[j] = d[j] ^ splitKey[i*keysize+j]
		}
		d = diffuse(d, h)
	}
	for j := 0; j < keysize; j++ {
		d[j] = d[j] ^ splitKey[(stripes-1)*keysize+j]
	}
	return d, nil
}

func afSplit(key []byte, h hash.Hash, stripes int) ([]byte, error) {
	keysize := len(key)
	s := make([]byte, keysize*stripes)
	d := make([]byte, keysize)
	n, err := rand.Read(s[0 : (keysize-1)*stripes])
	if err != nil {
		return nil, err
	}
	if n != (keysize-1)*stripes {
		return nil, fmt.Errorf("short read when attempting to read random data: %d < %d", n, (keysize-1)*stripes)
	}
	for i := 0; i < stripes-1; i++ {
		for j := 0; j < keysize; j++ {
			d[j] = d[j] ^ s[i*keysize+j]
		}
		d = diffuse(d, h)
	}
	for j := 0; j < keysize; j++ {
		s[(stripes-1)*keysize+j] = d[j] ^ key[j]
	}
	return s, nil
}

func roundUpToMultiple(i, factor int) int {
	if i < 0 {
		return 0
	}
	return i + ((factor - (i % factor)) % factor)
}

func hasherByName(name string) (func() hash.Hash, error) {
	switch name {
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	case "ripemd160":
		return ripemd160.New, nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", name)
	}
}
