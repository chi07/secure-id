package main

import (
	"fmt"

	secureid "github.com/chi07/secure-id/v2"
)

func main() {
	for i := 0; i < 20; i++ {
		id, err := secureid.NewSID(12)
		if err != nil {
			panic(err)
		}
		fmt.Println(id)
	}
}
