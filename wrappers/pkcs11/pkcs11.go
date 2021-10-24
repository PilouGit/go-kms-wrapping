package pkcs11

import (
	"C"
	"context"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"unsafe"

	"github.com/ThalesIgnite/crypto11"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	uuid "github.com/hashicorp/go-uuid"
)

// Wrapper represents credentials and Key information for the KMS Key used to
// encryption and decryption
type Wrapper struct {
	logger hclog.Logger

	keylabel  string
	context   *crypto11.Context
	secretKey *crypto11.SecretKey
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

func (k *Wrapper) Debug(msg string, args ...interface{}) {
	if k.logger != nil {
		k.logger.Debug(msg)
	} else {
		fmt.Printf(msg)
	}
}

// NewWrapper creates a new PKCS11 wrapper with the provided options
func NewWrapper(opts *wrapping.WrapperOptions) *Wrapper {
	if opts == nil {
		opts = new(wrapping.WrapperOptions)
	}
	k := &Wrapper{

		logger: opts.Logger,
	}
	return k
}

func (k *Wrapper) Init(_ context.Context) error {
	k.Debug("Init")
	return nil

}

func (k *Wrapper) Encrypt(_ context.Context, plaintext, aad []byte) (blob *wrapping.EncryptedBlobInfo, err error) {

	k.Debug("Encrypt")
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.NewEnvelope(nil).Encrypt(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	iv := make([]byte, k.secretKey.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err.Error())
	}
	blockModeCloser, err := k.secretKey.NewCBCEncrypterCloser(iv)
	if err != nil {
		return nil, fmt.Errorf("error in creating CBC encrypter: %w", err)
	}
	secretaeadkey := env.Key
	lensecretaeadkey := len(secretaeadkey)
	sizeciphertext := (int)(k.secretKey.BlockSize()) + lensecretaeadkey
	ciphertext := make([]byte, sizeciphertext)

	blockModeCloser.CryptBlocks(ciphertext[aes.BlockSize:], secretaeadkey)
	wrappedKey := append(iv, ciphertext...)
	ret := &wrapping.EncryptedBlobInfo{
		Ciphertext: env.Ciphertext,
		IV:         env.IV,
		KeyInfo: &wrapping.KeyInfo{

			Mechanism:  (uint64)(k.secretKey.Cipher.CBCMech),
			KeyID:      k.KeyID(),
			WrappedKey: wrappedKey,
		}}

	return ret, nil

}

func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.EncryptedBlobInfo, aad []byte) (pt []byte, err error) {

	k.Debug("Decrypt")

	if in == nil {
		return nil, errors.New("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	wrappedKey := in.KeyInfo.WrappedKey

	iv, ciphertext := wrappedKey[:16], wrappedKey[32:]
	decrypter, err := k.secretKey.NewCBCDecrypterCloser(iv)
	if err != nil {
		return nil, fmt.Errorf("error in creating CBC dencrypter: %w", err)
	}
	decrypter.CryptBlocks(ciphertext, ciphertext)
	envInfo := &wrapping.EnvelopeInfo{
		Key:        ciphertext,
		IV:         in.IV,
		Ciphertext: in.Ciphertext,
	}
	return wrapping.NewEnvelope(nil).Decrypt(envInfo, aad)
}

func (k *Wrapper) Finalize(_ context.Context) error {
	k.Debug("PKCS11::Finalize")

	if k.context != nil {

		return k.context.Close()
	}
	return nil
}
func bytesToUlong(bs []byte) (n uint) {
	sliceSize := len(bs)
	if sliceSize == 0 {
		return 0
	}

	value := *(*uint)(unsafe.Pointer(&bs[0]))
	if sliceSize > C.sizeof_ulong {
		return value
	}

	// truncate the value to the # of bits present in the byte slice since
	// the unsafe pointer will always grab/convert ULONG # of bytes
	var mask uint
	for i := 0; i < sliceSize; i++ {
		mask |= 0xff << uint(i*8)
	}
	return value & mask
}

func (k *Wrapper) KeySize(secretKey *crypto11.SecretKey) (uint, error) {

	attr, error := k.context.GetAttributes(secretKey,
		[]crypto11.AttributeType{crypto11.CkaValueLen})
	if error != nil {
		return 0, error
	}
	return bytesToUlong(attr[crypto11.CkaValueLen].Value), nil

}

// Type returns the wrapping type for this particular Wrapper implementation
func (k *Wrapper) Type() string {
	k.Debug("pkcs11::Type")
	return wrapping.PKCS11
}

// KeyID returns the last known key id
func (k *Wrapper) KeyID() string {
	k.Debug("pkcs11::KeyID")
	return k.keylabel
}

// HMACKeyID returns the last known HMAC key id
func (k *Wrapper) HMACKeyID() string {
	return ""
}
func (s *Wrapper) GenerateSecretKey(keylabel string) {

	id, err := uuid.GenerateRandomBytes(32)
	if err != nil {
		fmt.Errorf("error wrapping data: %w", err)
	}
	key, err := s.context.GenerateSecretKeyWithLabel(id, []byte(keylabel), 256, crypto11.CipherAES)
	if err != nil {
		fmt.Errorf("error wrapping data: %w", err)
	}
	s.secretKey = key

}
func (s *Wrapper) SetConfig(config map[string]string) (map[string]string, error) {

	s.Debug("SetConfig")
	if config == nil {
		config = map[string]string{}
	}
	crypto11Config := &crypto11.Config{}
	var libpath string = config["lib"]
	if libpath == "" {
		return nil, fmt.Errorf("lib parameter is not found in this configuration")
	}

	crypto11Config.Path = libpath
	s.Debug("pkcs11::SetConfig(%w)", crypto11Config.Path)

	var slot string = config["slot"]
	if slot == "" {
		var tokenLabel string = config["token"]
		if tokenLabel == "" {
			return nil, fmt.Errorf("token parameter is not found in this configuration")
		} else {
			crypto11Config.TokenLabel = tokenLabel
		}
	} else {

		var slotnumber, err = strconv.ParseUint(slot, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("slot %s is not a number", slot)
		}
		slotInt := int(slotnumber)
		crypto11Config.SlotNumber = &slotInt
	}
	var pin string = config["pin"]
	if pin != "" {
		crypto11Config.Pin = pin

	} else {
		pin = os.Getenv("HSM_PIN")
		if pin != "" {

			os.Setenv("HSM_PIN", "666")
			crypto11Config.Pin = pin
		} else {
			return nil, fmt.Errorf("pin parameter is not found in this configuration")
		}
	}

	keylabel := config["key_label"]
	if keylabel == "" {
		return nil, fmt.Errorf("no key label was given")
	} else {
		s.keylabel = keylabel
	}

	context, err := crypto11.Configure(crypto11Config)
	if err != nil {
		return nil, fmt.Errorf("Error in configure HSM %s", err.Error())
	}
	s.context = context
	generate_key, _ := strconv.ParseBool(config["generate_key"])
	if generate_key {
		s.GenerateSecretKey(s.keylabel)
	} else {
		secretkey, err := s.context.FindKey(nil, []byte(s.keylabel))
		if err != nil {
			return nil, fmt.Errorf("error in finding key: %w", err)
		}
		if secretkey == nil {
			return nil, fmt.Errorf("No Secret Key with %s found in finding key", s.keylabel)
		}
		if err != nil {
			return nil, fmt.Errorf("error in finding key size: %w", err)
		}
		s.secretKey = secretkey
	}
	wrapperInfo := make(map[string]string)
	wrapperInfo["libpath"] = crypto11Config.Path
	return wrapperInfo, nil
}
