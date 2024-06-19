package secureid

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"
)

var mutex sync.Mutex

// NewSID generates a secure ID with the specified length.
// The ID is generated by combining a base36-encoded timestamp with a base36-encoded random number.
// The timestamp is the current time in milliseconds since the Unix epoch.
// The random number is a 2-byte value generated using the crypto/rand package.
// The length parameter specifies the total length of the ID, including both the timestamp and random number parts.
// The timestamp part will be padded with zeros on the left to ensure it has the correct length.
// The random number part will be padded with zeros on the left to ensure it has a length of 3 characters.
// The function returns an error if the length is less than 5 characters.
func NewSID(length int) (string, error) {
	if length < 5 {
		return "", fmt.Errorf("length must be at least 5 characters")
	}

	mutex.Lock()
	defer mutex.Unlock()

	now := time.Now().UnixNano() / 1e6
	timePartLength := length - 3

	var randomBytes [2]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", fmt.Errorf("random number generation failed: %v", err)
	}
	randomPart := binary.BigEndian.Uint16(randomBytes[:])

	base36Time := padLeft(strconv.FormatInt(now%int64(math.Pow(36, float64(timePartLength))), 36), timePartLength, "0")
	base36Random := padLeft(strconv.FormatInt(int64(randomPart)%46656, 36), 3, "0")

	return base36Time + base36Random, nil
}

func padLeft(str string, length int, pad string) string {
	for len(str) < length {
		str = pad + str
	}
	return str
}

// IsSecureID validates a string ID generated by GenerateSecureID.
// It checks if the ID has the correct length and if both parts of the ID (time and random) are valid base36-encoded integers.
func IsSecureID(id string, length int) bool {
	if len(id) != length {
		return false
	}

	// Extract the time and random parts from the ID
	timePart := id[:len(id)-3]
	randomPart := id[len(id)-3:]

	// Basic pattern check: Ensure the time part contains at least one digit if it is not empty
	containsDigit := len(timePart) == 0
	if len(timePart) > 0 {
		for _, char := range timePart {
			if char >= '0' && char <= '9' {
				containsDigit = true
				break
			}
		}
		if !containsDigit {
			return false
		}
	}

	// Validate the time part as a base36-encoded integer if it is not empty
	if len(timePart) > 0 {
		_, err := strconv.ParseInt(timePart, 36, 64)
		if err != nil {
			return false
		}
	}

	// Validate the random part as a base36-encoded integer
	_, err := strconv.ParseInt(randomPart, 36, 64)
	if err != nil {
		return false
	}

	return true
}