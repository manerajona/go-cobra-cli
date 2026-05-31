package aesgcm

import (
	"testing"
)

func TestNewEncryptor(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		iv      string
		wantErr bool
		errMsg  string // Optional: check error message
	}{
		{
			name:    "valid 256-bit key and 128-bit IV",
			key:     "0123456789012345678901234567890123456789012345678901234567890123", // 64 chars = 256 bits
			iv:      "01234567890123456789012345678901",                                 // 32 chars = 128 bits
			wantErr: false,
		},
		{
			name:    "key too short",
			key:     "short",
			iv:      "01234567890123456789012345678901",
			wantErr: true,
		},
		{
			name:    "key too long",
			key:     "01234567890123456789012345678901234567890123456789012345678901234567890123456789",
			iv:      "01234567890123456789012345678901",
			wantErr: true,
		},
		{
			name:    "IV too short",
			key:     "0123456789012345678901234567890123456789012345678901234567890123",
			iv:      "short",
			wantErr: true,
		},
		{
			name:    "IV too long",
			key:     "0123456789012345678901234567890123456789012345678901234567890123",
			iv:      "012345678901234567890123456789012345",
			wantErr: true,
		},
		{
			name:    "empty key and IV",
			key:     "",
			iv:      "",
			wantErr: true,
		},
		{
			name:    "empty key",
			key:     "",
			iv:      "01234567890123456789012345678901",
			wantErr: true,
		},
		{
			name:    "empty IV",
			key:     "0123456789012345678901234567890123456789012345678901234567890123",
			iv:      "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewEncryptor(tt.key, tt.iv)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewEncryptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && got != nil {
				t.Errorf("NewEncryptor() expected nil encryptor for error case, got %v", got)
			}

			if !tt.wantErr && got == nil {
				t.Errorf("NewEncryptor() expected non-nil encryptor, got nil")
			}
		})
	}
}

func Test_encryptor_Encrypt(t *testing.T) {
	// Create a valid encryptor once for all tests
	encryptor := createTestEncryptor(t)

	tests := []struct {
		name      string
		encryptor Encryptor
		plaintext string
		secret    string
		wantErr   bool
	}{
		{
			name:      "encrypt simple plaintext",
			encryptor: encryptor,
			plaintext: "Hello, World!",
			secret:    "hxYJGh8EZ518I54SXkhnWoEqKFMMbJgry9LYxHc=",
			wantErr:   false,
		},
		{
			name:      "encrypt empty plaintext",
			encryptor: encryptor,
			plaintext: "",
			secret:    "",
		},
		{
			name:      "encrypt long plaintext",
			encryptor: encryptor,
			plaintext: `
The quick brown fox jumps over the lazy dog. 
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.`,
			secret:  "xScNE1BZMqNwOtIUDXdv4udiLu1GmQcLUtT9VFTJBrIsnjkcP6Nbl7QXnKC9sq0ZyWvtT/ukO7HowkSWg2A3DP+dsaLvoVqn1roYYcHvdyL/ziUimc84tbWYagL63XkXRI5iCuSrSmh1Ykj4Qzw/60i031qLnQY1qB140yzVHQxopk05tTAEzRtjZ38lJW7F/0xxI184AqY=",
			wantErr: false,
		},
		{
			name:      "encrypt unicode text",
			encryptor: encryptor,
			plaintext: "Hello 🌍 世界 مرحبا мир",
			secret:    "hxYJGh8It1Wf3NKSx47/GUskmBC+QqrL+g8FnAJ8yELgJ9xeN0C2gebw5nR+YX2PmcTn",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptor.Encrypt(tt.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.secret {
				t.Errorf("Encrypt() got = %v, want %v", got, tt.secret)
			}
		})
	}
}

func Test_encryptor_Decrypt(t *testing.T) {
	// Create a valid encryptor once for all tests
	encryptor := createTestEncryptor(t)

	tests := []struct {
		name      string
		encryptor Encryptor
		plaintext string
		secret    string
		wantErr   bool
	}{
		{
			name:      "decrypt simple plaintext",
			encryptor: encryptor,
			plaintext: "Hello, World!",
			secret:    "hxYJGh8EZ518I54SXkhnWoEqKFMMbJgry9LYxHc=",
			wantErr:   false,
		},
		{
			name:      "decrypt empty plaintext",
			encryptor: encryptor,
			plaintext: "",
			secret:    "",
		},
		{
			name:      "decrypt long plaintext",
			encryptor: encryptor,
			plaintext: `
The quick brown fox jumps over the lazy dog. 
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.`,
			secret:  "xScNE1BZMqNwOtIUDXdv4udiLu1GmQcLUtT9VFTJBrIsnjkcP6Nbl7QXnKC9sq0ZyWvtT/ukO7HowkSWg2A3DP+dsaLvoVqn1roYYcHvdyL/ziUimc84tbWYagL63XkXRI5iCuSrSmh1Ykj4Qzw/60i031qLnQY1qB140yzVHQxopk05tTAEzRtjZ38lJW7F/0xxI184AqY=",
			wantErr: false,
		},
		{
			name:      "decrypt unicode text",
			encryptor: encryptor,
			plaintext: "Hello 🌍 世界 مرحبا мир",
			secret:    "hxYJGh8It1Wf3NKSx47/GUskmBC+QqrL+g8FnAJ8yELgJ9xeN0C2gebw5nR+YX2PmcTn",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptor.Decrypt(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.plaintext {
				t.Errorf("Decrypt() got = %v, want %v", got, tt.plaintext)
			}
		})
	}
}

func createTestEncryptor(t *testing.T) Encryptor {
	t.Helper()
	key := "0123456789012345678901234567890123456789012345678901234567890123"
	iv := "01234567890123456789012345678901"
	enc, err := NewEncryptor(key, iv)
	if err != nil {
		t.Fatalf("Failed to create test encryptor: %v", err)
	}
	return enc
}
