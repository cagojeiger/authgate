package storage

import "golang.org/x/crypto/bcrypt"

func verifyBcrypt(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
