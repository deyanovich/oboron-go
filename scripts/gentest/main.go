package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"

	"oboron.org/go/oboron"
	"oboron.org/go/oboron/ztier"
)

const (
	minLength = 1
	maxLength = 100
)

type vector struct {
	Scheme string `json:"scheme"`
	Key    string `json:"key"`
	In     string `json:"in"`
	Out    string `json:"out"`
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@#$%^&*()_+-=[]{}|;:,.<>?/"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[mrand.IntN(len(charset))]
	}
	return string(result)
}

func deterministicStr(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= len(charset) {
		return charset[:length]
	}
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)]
	}
	return string(result)
}

func generateRandomMasterKey() (*oboron.MasterKey, error) {
	raw := make([]byte, oboron.MasterKeySize)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return oboron.NewMasterKey(raw)
}

func main() {
	schemes := []oboron.Scheme{oboron.SchemeAasv, oboron.SchemeZrbcx}
	for _, scheme := range schemes {
		for inputLen := minLength; inputLen <= maxLength; inputLen++ {
			mk, err := generateRandomMasterKey()
			if err != nil {
				fmt.Printf("Error generating key: %v\n", err)
				continue
			}
			genVector(mk, scheme, inputLen)
		}
	}
}

func genVector(mk *oboron.MasterKey, scheme oboron.Scheme, inputLen int) {
	s := deterministicStr(inputLen)

	out, err := encode(mk, scheme, s)
	if err != nil {
		fmt.Printf("Error encoding: %v\n", err)
		return
	}

	vec := vector{
		Scheme: string(scheme),
		Key:    mk.Base64(),
		In:     s,
		Out:    out,
	}
	j, _ := json.Marshal(vec)
	fmt.Println(string(j))
}

// encode produces the b32 obtext for a scheme. The a/u tier uses Omnib (master
// key); the z tier uses Omnibz with the secret derived from the master key's
// first 32 bytes — byte-identical to the pre-split unified codec.
func encode(mk *oboron.MasterKey, scheme oboron.Scheme, s string) (string, error) {
	format := string(scheme) + ".b32"
	if scheme.IsZTier() {
		sec, err := ztier.SecretFromMasterKey(mk)
		if err != nil {
			return "", err
		}
		ob, err := ztier.NewOmnibz(sec.Hex())
		if err != nil {
			return "", err
		}
		return ob.Enc(s, format)
	}
	ob, err := oboron.NewOmnib(mk.Hex())
	if err != nil {
		return "", err
	}
	return ob.Enc(s, format)
}
