package base

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg/auth"
	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg/models"
	"github.com/buraktabakoglu/TODO_APP_AUTH/pkg/utils"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func (server *Server) Login(c *gin.Context) {

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status":      http.StatusUnprocessableEntity,
			"first error": "Unable to get request",
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

	user.Prepare()
	errList = user.Validate("login")
	if err != nil {
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

func (server *Server) SignIn(email, password string) (string, error) {

	var err error

	user := models.User{}

	err = server.DB.Debug().Model(models.User{}).Where("email = ?", email).Take(&user).Error
	if err != nil {
		return "", err
	}
	err = models.VerifyPassword(user.Password, password)
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return "", err
	}
	return auth.CreateToken(uint32(user.ID))
}

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
