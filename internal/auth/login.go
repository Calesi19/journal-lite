package auth

import (
	"database/sql"
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

const SecretKey = "your-super-duper-secret-magic-key-of-power"

type Account struct {
	Id           float64
	Username     string
	PasswordHash string
}

func Login(db *sql.DB, username string, password string) (LoginResponse, error) {
	var account Account

	err := db.QueryRow("SELECT id, username, password_hash FROM accounts WHERE username = ?", username).
		Scan(&account.Id, &account.Username, &account.PasswordHash)
	if err != nil {
		res := LoginResponse{
			IsSuccess: false,
		}
		return res, errors.New("Invalid username or password.")
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password))
	if err != nil {
		res := LoginResponse{
			IsSuccess: false,
		}
		return res, errors.New("Invalid username or password.")
	}

	bearerToken, err := generateBearerToken(account)
	if err != nil {
		res := LoginResponse{
			IsSuccess: false,
		}
		return res, errors.New("Error occurred while generating the bearer token.")
	}

	refreshToken, err := generateRefreshToken(account)
	if err != nil {
		res := LoginResponse{
			IsSuccess: false,
		}
		return res, errors.New("Error occurred while generating the refresh token.")
	}

	res := LoginResponse{
		IsSuccess:    true,
		BearerToken:  bearerToken,
		RefreshToken: refreshToken,
	}

	return res, nil
}

type LoginResponse struct {
	IsSuccess    bool
	BearerToken  string
	RefreshToken string
}

func generateBearerToken(account Account) (string, error) {
	claims := jwt.MapClaims{
		"accountId": account.Id,
		"username":  account.Username,
		"exp":       time.Now().Add(time.Hour * 5).Unix(),
		"iat":       time.Now().Unix(),
		"iss":       "journal-lite",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	bearerToken, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}

	return bearerToken, nil
}

func generateRefreshToken(account Account) (string, error) {
	claims := jwt.MapClaims{
		"accountId": account.Id,
		"username":  account.Username,
		"exp":       time.Now().Add(time.Hour * 72).Unix(),
		"iat":       time.Now().Unix(),
		"iss":       "journal-lite",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refreshToken, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}
