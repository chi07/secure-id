# Simple Secure ID

This is a simple ID generator that generates a random ID of a given length.

# Usage


```go
func main() {
	for i := 0; i < 10; i++ {
		id, err := NewSID(9) // Example: Request an ID of length 9
		if err != nil {
			fmt.Println("Error generating ID:", err)
			return
		}
		fmt.Println(id)
	}

}
```

# Benchmarks

```shell
go test -bench=.
goos: darwin
goarch: arm64
pkg: github.com/chi07/secure-id
BenchmarkGenerateSecureID/Length5-12             3106658               365.3 ns/op
BenchmarkGenerateSecureID/Length10-12            3087804               388.4 ns/op
BenchmarkGenerateSecureID/Length15-12            2491728               479.4 ns/op
BenchmarkGenerateSecureID/Length20-12            2005977               608.6 ns/op
PASS
ok      github.com/chi07/secure-id      6.862s

```