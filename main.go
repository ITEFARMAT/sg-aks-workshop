package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	cache "github.com/patrickmn/go-cache"

	"golang.org/x/crypto/bcrypt"
)

// AppContext - An application context that contains anything required by the handlers
type AppContext struct {
	DB *cache.Cache
}

//Auth - simple auth token
type Auth struct {
	Token string `json:"token"`
}

//User - simple user struct
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
}

func main() {
	db := cache.New(cache.NoExpiration, cache.NoExpiration)
	username := "nimalo"
	password := []byte("Secret Password!")
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if err != nil {
		log.Fatal(err)
	}
	u := User{Username: username, PasswordHash: string(hash)}
	db.Set(u.Username, u, cache.NoExpiration)

	a := &AppContext{
		DB: db,
	}

	http.HandleFunc("/login", a.loginHandler)
	http.HandleFunc("/user", a.userHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func (a *AppContext) loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	var user User
	if u, found := a.DB.Get(username); found {
		user = u.(User)
	}

	// Compare the plain-text password with the stored hash
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))

	// If a user isn't found OR passwords don't match return an error
	if user.Username != username || err != nil {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	//Generate an auth token user CSPRNG
	bytes := make([]byte, 128)
	_, err = rand.Read(bytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(bytes)
	auth := Auth{Token: token}

	// Store the auth token and associate it with the user
	// Note - don't do this in prod, you'll also need to
	// think about a token invalidation strategy
	a.DB.Set(auth.Token, user.Username, cache.DefaultExpiration)

	js, err := json.Marshal(auth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func (a *AppContext) userHandler(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	idToken := strings.TrimSpace(strings.Replace(authorization, "Bearer", "", 1))

	var username string
	if u, found := a.DB.Get(idToken); found {
		username = u.(string)
	}

	if username == "" {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	user := User{Username: username}
	js, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}
