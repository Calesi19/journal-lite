package main

import (
	"fmt"
	"html/template"
	"io"
	"journal-lite/internal/accounts"
	"journal-lite/internal/auth"
	"journal-lite/internal/database"
	"journal-lite/internal/health"
	"journal-lite/internal/posts"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name+".html", data)
}

func newTemplate() *Template {
	return &Template{
		templates: template.Must(template.New("").Funcs(template.FuncMap{
			"formatDate": func(date string) string {
				t, err := time.Parse(time.RFC3339, date)
				if err != nil {
					return date
				}
				return t.Format("January 2, 2006")
			},
		}).ParseGlob("views/*.html")),
	}
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())

	e.Renderer = newTemplate()

	database.Initialize()

	e.GET("/", func(c echo.Context) error {
		return c.Render(200, "index", nil)
	})

	e.GET("/feed", func(c echo.Context) error {
		posts, err := GetPostsByAccountID(1)
		if err != nil {
			posts = []Post{}
		}

		return c.Render(200, "feed-page", posts)
	})

	e.GET("/posts", func(c echo.Context) error {
		posts, err := GetPostsByAccountID(1)
		if err != nil {
			posts = []Post{}
		}

		return c.Render(200, "posts", posts)
	})

	e.GET("/register", func(c echo.Context) error {
		return c.Render(200, "register-box", nil)
	})

	e.POST("/register", func(c echo.Context) error {
		username := c.FormValue("username")
		password := c.FormValue("password")
		passwordConfirmation := c.FormValue("password-confirmation")

		if password != passwordConfirmation {
			message := LoginBoxMessage{
				IsInvalidAttempt: true,
				Message:          "Passwords do not match",
			}

			return c.Render(200, "register-box", message)
		}

		newAccount := accounts.Account{
			Username:     username,
			PasswordHash: password,
		}

		_, err := accounts.CreateAccount(database.Db, newAccount)
		if err != nil {
			message := LoginBoxMessage{
				IsInvalidAttempt: true,
				Message:          "Failed to create account: " + err.Error(),
			}

			return c.Render(200, "register-box", message)
		}

		message := LoginBoxMessage{
			IsInvalidAttempt: false,
			Message:          "Account created successfully",
		}

		return c.Render(201, "register-account-complete", message)
	})

	e.GET("/open-delete-modal/:id", func(c echo.Context) error {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return c.String(http.StatusBadRequest, "Invalid ID format")
		}

		post := posts.GetPost(database.Db, 1, id)

		return c.Render(200, "delete-modal", post)
	})

	e.GET("/open-edit-modal/:id", func(c echo.Context) error {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return c.String(http.StatusBadRequest, "Invalid ID format")
		}

		post := posts.GetPost(database.Db, 1, id)

		return c.Render(200, "edit-modal", post)
	})

	e.PATCH("/posts/:id", func(c echo.Context) error {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return c.String(http.StatusBadRequest, "Invalid ID format")
		}

		content := c.FormValue("content")

		err = posts.UpdatePost(database.Db, content, id)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Error deleting post")
		}

		return c.Render(200, "empty-div", nil)
	})

	e.DELETE("/posts/:id", func(c echo.Context) error {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return c.String(http.StatusBadRequest, "Invalid ID format")
		}

		err = posts.DeletePost(database.Db, id)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Error deleting post")
		}

		return c.Render(200, "empty-div", nil)
	})

	e.GET("/open-create-modal", func(c echo.Context) error {
		return c.Render(200, "create-modal", nil)
	})

	e.GET("/close-modal", func(c echo.Context) error {
		return c.Render(200, "empty-div", nil)
	})

	e.POST("/create-post", func(c echo.Context) error {
		newPost := posts.Post{
			Content:   c.FormValue("content"),
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: time.Now().Format(time.RFC3339),
			AccountId: 1,
		}

		createdPost, err := posts.CreatePost(database.Db, newPost)
		if err != nil {
			return c.HTML(http.StatusInternalServerError, "Error creating post:"+err.Error())
		}

		return c.Render(201, "created-post-successfully", createdPost)
	})

	e.GET("/search", func(c echo.Context) error {
		params := posts.QueryParams{
			AccountId:  1,                      // Make sure to pass the current user's account ID
			SearchText: c.QueryParam("search"), // This matches the input name="search" from HTMX
			PageSize:   10,                     // Add your desired page size
			PageNumber: 1,                      // Start with first page
		}

		posts := posts.GetPosts(database.Db, params)

		return c.Render(200, "feed", posts)
	})

	e.GET("/edit/:id", func(c echo.Context) error {
		return c.Render(200, "edit-post", nil)
	})

	e.GET("health", health.HealthCheckHandler(database.Db))

	e.POST("/login", func(c echo.Context) error {
		username := c.FormValue("username")
		password := c.FormValue("password")

		tokens, err := auth.Login(database.Db, username, password)
		if err != nil {
			message := LoginBoxMessage{
				IsInvalidAttempt: true,
				Message:          err.Error(),
			}
			return c.Render(http.StatusUnauthorized, "index", message)
		}

		if tokens.IsSuccess {

			bearerCookie := http.Cookie{
				Name:     "bearerToken",
				Value:    tokens.BearerToken,
				Expires:  time.Now().Add(24 * time.Hour),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
			}
			refreshCookie := http.Cookie{
				Name:     "refreshToken",
				Value:    tokens.RefreshToken,
				Expires:  time.Now().Add(3 * 24 * time.Hour),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			}

			c.SetCookie(&bearerCookie)
			c.SetCookie(&refreshCookie)

			return c.Redirect(http.StatusFound, "/feed")
		}

		message := LoginBoxMessage{
			IsInvalidAttempt: true,
			Message:          "Invalid Credentials",
		}

		return c.Render(http.StatusUnauthorized, "index", message)
	})

	e.DELETE("/logout", func(c echo.Context) error {
		bearerCookie := http.Cookie{
			Name:    "bearerToken",
			Value:   "",
			Expires: time.Now().Add(-1 * time.Hour),
			Path:    "/",
		}

		refreshCookie := http.Cookie{
			Name:    "refreshToken",
			Value:   "",
			Expires: time.Now().Add(-1 * time.Hour),
			Path:    "/",
		}

		c.SetCookie(&bearerCookie)
		c.SetCookie(&refreshCookie)

		return c.HTML(http.StatusOK, `<script>window.location.href = "/";</script>`)
	})

	e.Start(":8080")
}

type Post struct {
	Id        int    `db:"id"`
	Content   string `db:"content"`
	CreatedAt string `db:"created_at"`
	UpdatedAt string `db:"updated_at"`
	AccountId int    `db:"account_id"`
}

type LoginBoxMessage struct {
	IsInvalidAttempt bool
	Message          string
}

func GetPostsByAccountID(accountID int) ([]Post, error) {
	if database.Db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := `
        SELECT id, content, created_at, updated_at, account_id
        FROM posts
        WHERE account_id = ?
				ORDER BY created_at DESC;
    `

	rows, err := database.Db.Query(query, accountID)
	if err != nil {
		return nil, fmt.Errorf("query error: %w", err)
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var p Post
		if err := rows.Scan(
			&p.Id,
			&p.Content,
			&p.CreatedAt,
			&p.UpdatedAt,
			&p.AccountId,
		); err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		posts = append(posts, p)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return posts, nil
}
