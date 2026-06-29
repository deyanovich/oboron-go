package main

import (
	"fmt"
	"math/rand/v2"

	"oboron.org/go/oboron"
	"oboron.org/go/obu"
)

const (
	numSamples = 100000
	minLength  = 1
	maxLength  = 100
)

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@#$%^&*()_+-=[]{}|;:,.<>?/"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.IntN(len(charset))]
	}
	return string(result)
}

func main() {
	ob, _ := oboron.NewOmnibKeyless()
	ou, _ := obu.NewOmnibuKeyless()

	fmt.Println("Input Length | Min Zdcbc Output | Max Zdcbc Output | Zdcbc varies | Min Dsiv Output | Max Dsiv Output | Dsiv varies")
	fmt.Println("-------------|------------------|------------------|--------------|-----------------|-----------------|------------")

	for inputLen := minLength; inputLen <= maxLength; inputLen++ {
		minZdcbc := int(^uint(0) >> 1)
		maxZdcbc := 0
		minDsiv := int(^uint(0) >> 1)
		maxDsiv := 0

		for i := 0; i < numSamples; i++ {
			s := randomString(inputLen)

			encZdcbc, err := ou.Enc(s, "zdcbc.b32")
			if err != nil {
				fmt.Printf("Error encoding zdcbc: %v\n", err)
				continue
			}
			if len(encZdcbc) < minZdcbc {
				minZdcbc = len(encZdcbc)
			}
			if len(encZdcbc) > maxZdcbc {
				maxZdcbc = len(encZdcbc)
			}

			encDsiv, err := ob.Enc(s, "dsiv.b32")
			if err != nil {
				fmt.Printf("Error encoding dsiv: %v\n", err)
				continue
			}
			if len(encDsiv) < minDsiv {
				minDsiv = len(encDsiv)
			}
			if len(encDsiv) > maxDsiv {
				maxDsiv = len(encDsiv)
			}
		}

		zdcbcVaries := minZdcbc != maxZdcbc
		dsivVaries := minDsiv != maxDsiv
		fmt.Printf("%12d | %16d | %16d | %t | %15d | %15d | %t\n",
			inputLen, minZdcbc, maxZdcbc, zdcbcVaries, minDsiv, maxDsiv, dsivVaries)
	}
}
