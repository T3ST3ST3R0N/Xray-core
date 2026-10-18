package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = errors.New("Not Found")

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return errors.New("The cipher is not support Single-port Multi-user")
	}
	v.users = append(v.users, u)

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}

	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}
	v.users[idx].Cancel()
	ulen := len(v.users)

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

	return nil
}

// GetByEmail Get a Shadowsocks user with a non-empty Email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	for _, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(len(v.users))
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	v.RLock()
	defer v.RUnlock()

	var subkey [32]byte
	var nonce [24]byte
	var data []byte
	for _, user := range v.users {
		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			// AEAD payload decoding requires the payload to be over 32 bytes
			if len(bs) < 32 {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			if len(bs) < int(ivLen)+18 {
				continue
			}
			iv := bs[:ivLen]
			key := subkey[:aeadCipher.KeyBytes]
			hkdfSHA1(account.Key, iv, key)
			aead = aeadCipher.AEADAuthCreator(key)

			var matchErr error
			switch command {
			case protocol.RequestCommandTCP:
				if cap(data) < 2 {
					data = make([]byte, 2)
				}
				ret, matchErr = aead.Open(data[:0], nonce[:aead.NonceSize()], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				size := len(bs) - int(ivLen) - aead.Overhead()
				if size < 0 {
					continue
				}
				if cap(data) < size {
					data = make([]byte, size)
				}
				ret, matchErr = aead.Open(data[:0], nonce[:aead.NonceSize()], bs[ivLen:], nil)
			}

			if matchErr == nil {
				u = user
				return
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			return
		}
	}

	return nil, nil, nil, 0, ErrNotFound
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}
