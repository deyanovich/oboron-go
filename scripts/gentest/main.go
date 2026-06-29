package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"oboron.org/go/oboron"
	"oboron.org/go/obu"
)

const (
	minLength = 1
	maxLength = 100
)

type vector struct {
	Format    string `json:"format"`
	Key       string `json:"key"`
	Plaintext string `json:"plaintext"`
	Obtext    string `json:"obtext"`
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
	// dsiv (authenticated) and zdcbc (obu) are the deterministic schemes used
	// for self-test generation.
	schemes := []oboron.Scheme{oboron.SchemeDsiv, oboron.SchemeZdcbc}
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
		Format:    string(scheme) + ".b32",
		Key:       mk.Hex(),
		Plaintext: s,
		Obtext:    out,
	}
	j, _ := json.Marshal(vec)
	fmt.Println(string(j))
}

// encode produces the b32 obtext for a scheme. The authenticated tier uses
// Omnib (master key); the obu tier uses Omnibu with the secret derived from the
// master key's first 32 bytes.
func encode(mk *oboron.MasterKey, scheme oboron.Scheme, s string) (string, error) {
	format := string(scheme) + ".b32"
	if scheme.IsObu() {
		sec, err := obu.SecretFromMasterKey(mk)
		if err != nil {
			return "", err
		}
		ob, err := obu.NewOmnibu(sec.Hex())
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
