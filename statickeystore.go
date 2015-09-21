package restgate

import (
	"errors"
)

type keyStoreEntry struct {
	index  int
	secret string
}

type StaticKeyStore struct {
	keyStore map[string]keyStoreEntry
	keys     []string
}

func NewStaticKeyStore(storeSize int) *StaticKeyStore {
	return &StaticKeyStore{keyStore: make(map[string]keyStoreEntry), keys: make([]string, 0, storeSize)}
}

func NewStaticKeyStoreFromKeys(keyMap map[string]string) (*StaticKeyStore, error) {
	if keyMap == nil || len(keyMap) == 0 {
		return nil, errors.New("Invalid key set")
	}
	ks := NewStaticKeyStore(len(keyMap))
	for key, secret := range keyMap {
		ks.AddKey(key, secret)
	}
	return ks, nil
}

func (ks *StaticKeyStore) AddKey(key string, secret string) error {
	if ks.keyStore == nil || ks.keys == nil {
		return errors.New("StaticKeyStore not initialized")
	}
	if key == "" || len(key) == 0 {
		return errors.New("Cannot add empty key")
	}
	ks.keys = append(ks.keys, key)
	ks.keyStore[key] = keyStoreEntry{index: len(ks.keyStore), secret: secret}
	return nil
}

func (ks *StaticKeyStore) MatchKey(key string, secret string) (authenticationPassed bool, err error) {
	authenticationPassed = false
	err = nil
	if keyEntry, ok := ks.keyStore[key]; ok {
		if secureCompare(key, ks.keys[keyEntry.index]) { //Key matches
			if (keyEntry.secret == "" && secret == "") || secureCompare(secret, keyEntry.secret) {
				authenticationPassed = true
			}
		}
	}
	return authenticationPassed, err
}
