package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrTokenInvalidLength = errors.New("token length is invalid")
)

func b64encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func b64decode(data string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}

	return decoded
}

func oneTimePad(data, key []byte) error {
	n := len(data)
	if n != len(key) {
		return ErrTokenInvalidLength
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}

	return nil
}

const tokenLength2 = tokenLength * 2

func maskToken(data []byte) ([]byte, error) {
	if len(data) != tokenLength {
		return nil, ErrTokenInvalidLength
	}

	var (
		result = make([]byte, tokenLength2)
		key    = result[:tokenLength]
		token  = result[tokenLength:]
	)

	copy(token, data)

	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to read random data: %w", err)
	}

	if err := oneTimePad(token, key); err != nil {
		return nil, fmt.Errorf("failed to apply one time pad: %w", err)
	}

	return result, nil
}

func unmaskToken(data []byte) ([]byte, error) {
	if len(data) != tokenLength*2 {
		return nil, ErrTokenInvalidLength
	}

	key := data[:tokenLength]
	token := data[tokenLength:]

	if err := oneTimePad(token, key); err != nil {
		return nil, fmt.Errorf("failed to apply one time pad: %w", err)
	}

	return token, nil
}
