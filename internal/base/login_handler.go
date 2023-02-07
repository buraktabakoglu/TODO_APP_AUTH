package base

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg/auth"
	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg/models"
	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

/**
@Summary Login and get a JWT token
@Produce json
@Param user body models.User true "User email and password"
@Success 200 {object} models.Token
@Router /auth/login [post]
*/
func (server *Server) Login(c *gin.Context) {
	
	zap.S().Info("Received login request") //
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  "Unable to get request",
		})
		return
	}
	user := models.User{}
	err = json.Unmarshal(body, &user)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  "Cannot unmarshal body",
		})
		return
	}
	dbuser := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	host := os.Getenv("DB_HOST")

	db, err := sql.Open("postgres", fmt.Sprintf("user=%s password=%s dbname=%s host=%s sslmode=disable", dbuser, password, dbname, host))
	if err != nil {
		zap.S().Error("Failed to connect to the database", zap.Error(err)) // Adding log for database connection error
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to the database"})
		return
	}
	defer db.Close()

	// Check if the user is active in the database
	var isActive bool
	err = db.QueryRow("SELECT is_active FROM users WHERE email = $1", user.Email).Scan(&isActive)
	if err != nil {
		zap.S().Error("Failed to retrieve user information from the database", zap.Error(err)) 
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information from the database"})
		return
	}
	if !isActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "This account has been deactivated. Please contact an administrator"})
		return
	}

	user.Prepare()
	errList := user.Validate("login")
	if len(errList) > 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	token, err := server.SignIn(user.Email, user.Password)
	if err != nil {
		formattedError := utils.FormatError(err.Error())
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  formattedError,
		})

		return
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status":   http.StatusOK,
			"response": token,
		})
	}

}

//go log /// zap //
func (server *Server) SignIn(email, password string) (string, error) {
	var user models.User
	var err error

	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	sugar := logger.Sugar()

	sugar.Infow("Checking if user exists in the database",
		"email", email,
	)
	err = server.DB.Debug().Table("users").Select("id, password").Where("email = ?", email).Scan(&user).Error
	if err != nil {
		sugar.Errorw("Failed to retrieve user from the database",
			"error", err.Error(),
		)
		return "", err
	}

	sugar.Infow("Verifying user password",
		"email", email,
	)
	err = models.VerifyPassword(user.Password, password)
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		sugar.Errorw("Failed to verify user password",
			"error", err.Error(),
		)
		return "", err
	}

	sugar.Infow("Creating token for user",
		"user_id", user.ID,
	)
	token, err := auth.CreateToken(uint32(user.ID))
	if err != nil {
		sugar.Errorw("Failed to create token for user",
			"error", err.Error(),
		)
		return "", err
	}

	return token, nil
}

/**
@Summary Logout a user by blacklisting their token
@Description This function takes in the request context and extracts the token from it. It then connects to a Redis instance and adds the token to a "blacklisted_tokens" set.
@Tags User
@Accept json
@Produce json
@Success 200
@Failure 400
@Failure 401
@Failure 500
@Router /auth/logout [post]
*/
func (server *Server) Logout(c *gin.Context) {
	tokenString := auth.ExtractToken(c.Request)

	// Redis'e bağlan ve tokeni "blacklisted_tokens" setine ekle
	redisConn := auth.GetRedisConnection()
	if err := redisConn.SAdd("blacklisted_tokens", tokenString).Err(); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if err := auth.TokenValid(c.Request); err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	c.SetCookie("token", "", -1, "", "", false, true)
}
