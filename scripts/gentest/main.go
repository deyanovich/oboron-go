package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"

	"oboron.org/go/oboron"
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
			ob, err := oboron.NewOmnibFromMasterKey(mk)
			if err != nil {
				fmt.Printf("Error creating omnib: %v\n", err)
				continue
			}
			genVector(ob, mk, scheme, inputLen)
		}
	}
}

func genVector(ob *oboron.Omnib, mk *oboron.MasterKey, scheme oboron.Scheme, inputLen int) {
	s := deterministicStr(inputLen)

	out, err := ob.EncodeWithFormat(s, string(scheme)+".b32")
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
