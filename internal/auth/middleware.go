package auth

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

func ValidateToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		fmt.Println("ValidateToken")

		cookie, err := c.Cookie("bearerToken")
		if err != nil || cookie.Value == "" {
			return c.Redirect(http.StatusSeeOther, "/")
		}

		fmt.Println(cookie.Value)

		tokenString := cookie.Value
		token, err := parseToken(tokenString)
		if err != nil || !token.Valid {
			fmt.Println(err)
			return c.Redirect(http.StatusSeeOther, "/")
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			fmt.Println("claims not ok")
			fmt.Println(claims)
			return c.Redirect(http.StatusSeeOther, "/")
		}

		fmt.Println(claims)

		accountId, ok := claims["accountId"].(float64)
		if !ok || accountId == 0 {
			fmt.Println("accountId not ok")
			fmt.Println(accountId)
			return c.Redirect(http.StatusSeeOther, "/")
		}

		fmt.Println(accountId)

		c.Set("accountId", accountId)

		fmt.Println("ValidateToken end")

		return next(c)
	}
}

func parseToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, echo.NewHTTPError(401, "Unexpected signing method")
		}

		return []byte(SecretKey), nil
	})
}
