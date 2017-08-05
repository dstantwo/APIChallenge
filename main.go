package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	jwt_lib "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/contrib/jwt"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	tokenSecret = "otiOjJOVdUGzx6ST7fIBe7XoCPPT1WmQcSNlI1ElmbtaasRvim6OKSkUYyqXiS9U"
)

func main() {
	// connect to postgres db
	db, err := sql.Open("postgres", "user=app password=Bl2BPMhb9Dx1v5Uu dbname=app sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	// helper functions for passwords
	HashPassword := func(password string) (string, error) {
		bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
		return string(bytes), err
	}

	CheckPasswordHash := func(password, hash string) bool {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		return err == nil
	}

	UserNameFromAuthHeader := func(authHeader string) string {
		tokenString := strings.Replace(authHeader, "Bearer ", "", -1)
		// parse tokenString
		token, _ := jwt_lib.Parse(tokenString, func(token *jwt_lib.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt_lib.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(tokenSecret), nil
		})

		if claims, ok := token.Claims.(jwt_lib.MapClaims); ok && token.Valid {
			return claims["username"].(string)
		} else {
			return ""
		}
	}

	AuthHeaderCanAccessUserName := func(authHeader string, username string) bool {
		tokenString := strings.Replace(authHeader, "Bearer ", "", -1)
		var userId string
		err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&userId)
		if err != nil {
			return false
		}
		// parse tokenString
		token, err := jwt_lib.Parse(tokenString, func(token *jwt_lib.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt_lib.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(tokenSecret), nil
		})

		if claims, ok := token.Claims.(jwt_lib.MapClaims); ok && token.Valid {
			return claims["id"] == userId
		} else {
			return false
		}
	}

	AuthHeaderIsRevoked := func(authHeader string) bool {
		tokenString := strings.Replace(authHeader, "Bearer ", "", -1)
		var isRevoked bool
		err := db.QueryRow("SELECT isRevoked FROM tokens WHERE token = $1", tokenString).Scan(&isRevoked)
		if err != nil && err.Error() != "sql: no rows in result set" {
			return true
		}
		return isRevoked == true
	}

	AuthHeaderIsVerified := func(authHeader string) bool {
		tokenString := strings.Replace(authHeader, "Bearer ", "", -1)

		token, err := jwt_lib.Parse(tokenString, func(token *jwt_lib.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt_lib.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(tokenSecret), nil
		})
		if err == nil && token != nil {
			return true
		}
		return false
	}

	// declare types for validation
	type Login struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	// start server
	router := gin.Default()

	router.GET("/", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			if AuthHeaderIsVerified(authHeader) {
				username := UserNameFromAuthHeader(authHeader)
				if username != "" {

					// query db
					var id, additionalJsonString string
					err := db.QueryRow("SELECT id, additionalJson FROM users WHERE username = $1", username).Scan(&id, &additionalJsonString)
					if err == nil {
						// return results
						additionalJsonMap := make(map[string]interface{})
						errM := json.Unmarshal([]byte(additionalJsonString), &additionalJsonMap)
						if errM == nil {
							c.JSON(200, gin.H{
								"username":       username,
								"additionalJson": additionalJsonMap,
							})
							return
						}
					}
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
		return
	})

	userRoutes := router.Group("/user")
	{
		userRoutesPrivate := userRoutes.Group("").Use(jwt.Auth(tokenSecret))

		userRoutes.POST("/", func(c *gin.Context) {
			// parse request body
			var decodedBody map[string]string
			err = json.NewDecoder(c.Request.Body).Decode(&decodedBody)
			if err != nil {
				c.Status(400)
				return
			}

			// continue only if username & password in body
			password, okPass := decodedBody["password"]
			username, okUn := decodedBody["username"]
			if okPass && okUn {
				hashedPassword, err := HashPassword(password)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}

				// get any additional json fields as json string
				var additionalJson string
				delete(decodedBody, "username")
				delete(decodedBody, "password")
				if len(decodedBody) > 0 {
					result, err := json.Marshal(decodedBody)
					additionalJson = string(result)
					if err != nil {
						c.Status(500)
						return
					}
				}

				// add user to db
				var userId int
				errQ := db.QueryRow(`INSERT INTO users(username, password, additionalJson) VALUES($1, $2, $3) RETURNING id`, username, hashedPassword, additionalJson).Scan(&userId)
				if errQ == nil {
					c.JSON(200, gin.H{"userId": userId})
					return
				} else {
					c.JSON(500, gin.H{"error": errQ.Error()})
					return
				}
			} else {
				c.Status(400)
				return
			}
		})

		userRoutesPrivate.GET("/:username", func(c *gin.Context) {
			// check if requester can access :username
			authHeader := c.GetHeader("Authorization")
			if !AuthHeaderCanAccessUserName(authHeader, c.Param("username")) || AuthHeaderIsRevoked(authHeader) {
				c.Status(401)
				return
			}

			// query db
			var username, id, additionalJsonString string
			err := db.QueryRow("SELECT id, username, additionalJson FROM users WHERE username = $1", c.Param("username")).Scan(&id, &username, &additionalJsonString)
			if err != nil {
				c.JSON(500, gin.H{"err": err.Error()})
				return
			}

			// return results
			additionalJsonMap := make(map[string]interface{})
			errM := json.Unmarshal([]byte(additionalJsonString), &additionalJsonMap)
			if errM != nil {
				c.JSON(500, gin.H{"err": errM.Error()})
				return
			}
			c.JSON(200, gin.H{
				"id":             id,
				"username":       username,
				"additionalJson": additionalJsonMap,
			})
			return
		})

		userRoutesPrivate.PUT("/:username", func(c *gin.Context) {
			// check if requester can access :username
			authHeader := c.GetHeader("Authorization")
			if !AuthHeaderCanAccessUserName(authHeader, c.Param("username")) || AuthHeaderIsRevoked(authHeader) {
				c.Status(401)
				return
			}

			// parse request body; remove username & password if present
			var decodedBody map[string]string
			err = json.NewDecoder(c.Request.Body).Decode(&decodedBody)
			if err != nil {
				c.Status(400)
				return
			}
			delete(decodedBody, "username")
			delete(decodedBody, "password")
			if len(decodedBody) < 1 {
				c.Status(400)
				return
			}

			// get existing additional JSON Map from db
			var additionalJsonString string
			err := db.QueryRow("SELECT additionalJson FROM users WHERE username = $1", c.Param("username")).Scan(&additionalJsonString)
			if err != nil {
				c.JSON(501, gin.H{"err": err.Error()})
				return
			}
			additionalJsonMap := make(map[string]interface{})
			errM := json.Unmarshal([]byte(additionalJsonString), &additionalJsonMap)
			if errM != nil {
				c.JSON(500, gin.H{"err": errM.Error()})
				return
			}

			// merge existing additional JSON map with request body
			for key, value := range decodedBody {
				additionalJsonMap[key] = value
			}

			// write updated additional JSON to db
			var newAdditionalJsonString string
			result, err := json.Marshal(additionalJsonMap)
			newAdditionalJsonString = string(result)
			if err != nil {
				c.JSON(500, gin.H{"err": err.Error()})
				return
			}
			_, errU := db.Exec("UPDATE users SET additionalJson = $1 WHERE username = $2", newAdditionalJsonString, c.Param("username"))
			if errU != nil {
				c.JSON(500, gin.H{"err": errU.Error()})
				return
			}
			c.Status(200)
			return

		})

		userRoutesPrivate.DELETE("/:username", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			if !AuthHeaderCanAccessUserName(authHeader, c.Param("username")) || AuthHeaderIsRevoked(authHeader) {
				c.Status(401)
				return
			}
			_, err := db.Exec("DELETE FROM users WHERE username = $1", c.Param("username"))
			if err != nil {
				c.JSON(500, gin.H{"err": err.Error()})
				return
			}
			c.Status(200)
			return
		})

	}

	authRoutes := router.Group("/auth")
	{
		authRoutesPrivate := authRoutes.Group("").Use(jwt.Auth(tokenSecret))

		authRoutes.POST("/", func(c *gin.Context) {
			var loginJson Login
			if c.BindJSON(&loginJson) == nil {
				// lookup username in db & compare hashed password
				var dbHashedPassword string
				var userId string
				err := db.QueryRow("SELECT password, id FROM users WHERE username = $1", loginJson.Username).Scan(&dbHashedPassword, &userId)
				if err != nil {
					c.Status(401)
					return
				}
				// compare password hashes
				if !CheckPasswordHash(loginJson.Password, dbHashedPassword) {
					c.Status(401)
					return
				}
				// password verified
				token := jwt_lib.New(jwt_lib.GetSigningMethod("HS256"))
				token.Claims = jwt_lib.MapClaims{
					"id":       userId,
					"username": loginJson.Username,
					"exp":      time.Now().Add(time.Hour * 1).Unix(),
				}
				tokenString, err := token.SignedString([]byte(tokenSecret))
				if err != nil {
					c.JSON(500, gin.H{"message": "Could not generate token"})
					return
				}
				c.JSON(200, gin.H{"token": tokenString})
				return
			}
		})

		authRoutesPrivate.DELETE("/", func(c *gin.Context) {
			authHeader := c.GetHeader("Authorization")
			tokenString := strings.Replace(authHeader, "Bearer ", "", -1)
			if AuthHeaderIsRevoked(authHeader) {
				c.Status(401)
				return
			}

			_, err := db.Exec(`INSERT INTO tokens(token, isRevoked) VALUES($1, TRUE)`, tokenString)
			if err != nil {
				c.JSON(500, gin.H{"err": err.Error()})
				return
			}
			c.Status(200)
			return
		})
	}

	router.Run()
}
