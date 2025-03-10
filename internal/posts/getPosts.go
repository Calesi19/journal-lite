package posts

import (
	"database/sql"
	"log"
	"time"
)

type QueryParams struct {
	AccountId  float64 `query:"accountId"`
	SearchText string  `query:"searchText"`
	DateFrom   string  `query:"dateFrom"`
	DateTo     string  `query:"dateTo"`
	PageNumber int64   `query:"pageNumber"`
	PageSize   int64   `query:"pageSize"`
}

func GetPosts(db *sql.DB, params QueryParams) []Post {
	args := []interface{}{params.AccountId}
	query := `SELECT id, content, date_created AS dateCreated, date_updated AS dateUpdated, user_id AS userId
              FROM posts
              WHERE user_id = ?`

	if params.SearchText != "" {
		// SQLite uses LIKE (case insensitive by default) and ? for params
		query += " AND content ILIKE ?"
		args = append(args, "%"+params.SearchText+"%")
	}

	if params.DateFrom != "" {
		dateFrom, err := time.Parse("2006-01-02", params.DateFrom)
		if err != nil {
			return []Post{}
		}
		query += " AND date_created >= ?"
		args = append(args, dateFrom)
	}

	if params.DateTo != "" {
		dateTo, err := time.Parse("2006-01-02", params.DateTo)
		if err != nil {
			return []Post{}
		}
		query += " AND date_created <= ?"
		args = append(args, dateTo)
	}

	query += " ORDER BY date_created DESC"

	if params.PageNumber > 0 && params.PageSize > 0 {
		offset := (params.PageNumber - 1) * params.PageSize
		query += " LIMIT ? OFFSET ?"
		args = append(args, params.PageSize, offset)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying posts: %v", err)
		return []Post{}
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		err := rows.Scan(
			&post.Id,
			&post.Content,
			&post.CreatedAt,
			&post.UpdatedAt,
			&post.AccountId,
		)
		if err != nil {
			log.Printf("Error scanning post: %v", err)
			return []Post{}
		}
		posts = append(posts, post)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error after scanning posts: %v", err)
		return []Post{}
	}

	return posts
}

func GetPost(db *sql.DB, userId int64, postId int64) Post {
	query := `SELECT id, content, created_at, updated_at, account_id
              FROM posts
              WHERE id = ? AND account_id = ?`

	var post Post
	err := db.QueryRow(query, postId, userId).Scan(
		&post.Id,
		&post.Content,
		&post.CreatedAt,
		&post.UpdatedAt,
		&post.AccountId,
	)
	if err != nil {
		log.Printf("Error getting post: %v", err)
		return Post{}
	}

	return post
}
