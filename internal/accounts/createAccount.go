package accounts

import (
	"journal-lite/internal/database"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Account struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

func CreateAccountHandler(newAccount Account) error {

	hashedPassword, err := HashPassword(newAccount.PasswordHash)

	if err != nil {
		return err
	}

	newAccount.PasswordHash = hashedPassword

	err = AddAccountToDatabase(newAccount)

	if err != nil {
		return err
	}

	return nil
}

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func AddAccountToDatabase(newAccount Account) error {
	_, err := database.Db.Exec(
		"INSERT INTO accounts (username, password_hash, created_at) VALUES (?, ?, ?)",
		newAccount.Username,
		newAccount.PasswordHash,
		time.Now(),
	)
	if err != nil {
		return err
	}
	return nil
}

func GetAccountByUsername(username string) (*Account, error) {
	var account Account
	err := database.Db.QueryRow("SELECT * FROM accounts WHERE username = ?", username).
		Scan(&account.Username, &account.PasswordHash)
	if err != nil {
		return nil, err
	}

	return &account, nil
}
