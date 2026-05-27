package main

import (
	"fmt"
	"math/rand/v2"

	"oboron.org/go/oboron"
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

	fmt.Println("Input Length | Min Zrbcx Output | Max Zrbcx Output | Zrbcx varies | Min Aasv Output | Max Aasv Output | Aasv varies")
	fmt.Println("-------------|------------------|------------------|--------------|-----------------|-----------------|------------")

	for inputLen := minLength; inputLen <= maxLength; inputLen++ {
		minZrbcx := int(^uint(0) >> 1)
		maxZrbcx := 0
		minAasv := int(^uint(0) >> 1)
		maxAasv := 0

		for i := 0; i < numSamples; i++ {
			s := randomString(inputLen)

			encZrbcx, err := ob.EncodeZrbcx(s)
			if err != nil {
				fmt.Printf("Error encoding zrbcx: %v\n", err)
				continue
			}
			if len(encZrbcx) < minZrbcx {
				minZrbcx = len(encZrbcx)
			}
			if len(encZrbcx) > maxZrbcx {
				maxZrbcx = len(encZrbcx)
			}

			encAasv, err := ob.EncodeAasv(s)
			if err != nil {
				fmt.Printf("Error encoding aasv: %v\n", err)
				continue
			}
			if len(encAasv) < minAasv {
				minAasv = len(encAasv)
			}
			if len(encAasv) > maxAasv {
				maxAasv = len(encAasv)
			}
		}

		zrbcxVaries := minZrbcx != maxZrbcx
		aasvVaries := minAasv != maxAasv
		fmt.Printf("%12d | %16d | %16d | %t | %15d | %15d | %t\n",
			inputLen, minZrbcx, maxZrbcx, zrbcxVaries, minAasv, maxAasv, aasvVaries)
	}
}
