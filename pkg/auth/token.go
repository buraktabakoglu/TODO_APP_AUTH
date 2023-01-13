package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis"

	"github.com/dgrijalva/jwt-go"
)

func GetRedisConnection() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	return client
}

func CreateToken(user_id uint32) (string, error) {
	tokenKey := fmt.Sprintf("token:%d", user_id)
	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["user_id"] = user_id
	claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(os.Getenv("API_SECRET")))
	if err != nil {
		return "", err
	}

	redisConn := GetRedisConnection()
	redisConn.Set(tokenKey, signedToken, time.Hour)

	if err := redisConn.Set(tokenKey, signedToken, time.Hour).Err(); err != nil {
		return "", err
	}

	return signedToken, nil

}

func TokenValid(r *http.Request) error {
	tokenString := ExtractToken(r)

	redisConn := GetRedisConnection()

	// check if the token is in the blacklisted_tokens set
	if redisConn.SIsMember("blacklisted_tokens", tokenString).Val() {
		return fmt.Errorf("token is blacklisted")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("API_SECRET")), nil
	})
	if err != nil {
		return err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID := uint32(claims["user_id"].(float64))
		tokenKey := fmt.Sprintf("token:%d", userID)
		if redisConn.Exists(tokenKey).Val() == 0 {
			fmt.Println(tokenKey)
			return fmt.Errorf("invalid token")
		}
	}
	return nil
}

func ExtractToken(r *http.Request) string {
	keys := r.URL.Query()
	token := keys.Get("token")
	if token != "" {
		return token
	}
	bearerToken := r.Header.Get("Authorization")
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1]
	}
	return ""
}

func ExtractTokenID(r *http.Request) (uint32, error) {

	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("API_SECRET")), nil
	})
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		uid, err := strconv.ParseUint(fmt.Sprintf("%.0f", claims["user_id"]), 10, 64)
		if err != nil {
			return 0, err
		}
		return uint32(uid), nil
	}
	return 0, nil
}

func Pretty(data interface{}) {
	b, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println(string(b))
}
