package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type RefreshTokenResponse struct {
	IsSuccess    bool   `json:"isSuccess"`
	BearerToken  string `json:"bearerToken"`
	RefreshToken string `json:"refreshToken"`
}

func RefreshTokenHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		var req RefreshTokenRequest
		var account Account

		err := c.Bind(&req)
		if err != nil {
			return c.JSON(400, map[string]string{
				"message": "Invalid request.",
			})
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(
			req.RefreshToken,
			claims,
			func(token *jwt.Token) (interface{}, error) {
				return []byte(SecretKey), nil
			},
		)

		if err != nil || !token.Valid {
			return c.JSON(401, map[string]string{
				"message": "Invalid refresh token.",
			})
		}

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return c.JSON(401, map[string]string{
				"message": "Invalid signing method.",
			})
		}

		account.Id = claims["accountId"].(float64)
		account.Username = claims["email"].(string)

		bearerToken, err := generateBearerToken(account)
		if err != nil {
			return c.JSON(500, map[string]string{
				"message": "Error occurred while generating the bearer token.",
			})
		}

		refreshToken, err := generateRefreshToken(account)
		if err != nil {
			return c.JSON(500, map[string]string{
				"message": "Error occurred while generating the refresh token.",
			})
		}

		res := RefreshTokenResponse{
			IsSuccess:    true,
			BearerToken:  bearerToken,
			RefreshToken: refreshToken,
		}

		return c.JSON(200, res)
	}
}
