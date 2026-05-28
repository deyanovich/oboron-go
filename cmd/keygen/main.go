// Command keygen prints a freshly generated random master key (128-char
// hex) and exits — the convenience equivalent of "ob keygen", runnable
// without installing anything via "go run oboron.org/go/cmd/keygen".
// See https://oboron.org/.
package main

import (
	"fmt"

	"oboron.org/go/oboron"
)

func main() {
	fmt.Println(oboron.GenerateKey())
}
