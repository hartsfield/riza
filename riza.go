package riza

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/go-redis/redis"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	HmacSecret     string
	UsernameMin    int
	UsernameMax    int
	PasswordMin    int
	PasswordMax    int
	BlackList      []string
	MatchPW        *regexp.Regexp
	MatchUN        *regexp.Regexp
	RedisClient    *redis.Client
	RequestContext context.Context
}

func signin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var ctx context.Context
	ctx = context.WithValue(r.Context(), "credentials", &credentials{})
	hash, err := client.Get(r.Form["username"][0]).Result()
	if err != nil {
		fmt.Println(err)
	} else {
		doesMatch := checkPasswordHash(r.Form["password"][0], hash)
		if doesMatch {
			ctx = setTokenCookie(w, r)
		}
	}
	http.Redirect(w, r.WithContext(ctx), "/", http.StatusSeeOther)
}

func signup(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	hash, err := hashPassword(r.Form["password"][0])
	if err != nil {
		fmt.Println(err)
	}

	match, err := regexp.MatchString("^[A-Za-z0-9]+(?:[ _-][A-Za-z0-9]+)*$", r.Form["username"][0])
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("match: ", match)
	if match && (len(r.Form["username"]) < 25) {
		client.Set(r.Form["username"][0], hash, 0)
		ctx := setTokenCookie(w, r)
		http.Redirect(w, r.WithContext(ctx), "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func logout(w http.ResponseWriter, r *http.Request) {
	expire := time.Now().Add(10 * time.Minute)
	cookie := http.Cookie{Name: "token", Value: "loggedout", Path: "/", Expires: expire, MaxAge: 0}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func home(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value("credentials")
	if a, ok := c.(*credentials); ok && a.IsLoggedIn {
		err := templates.ExecuteTemplate(w, "home.tmpl", a)
		if err != nil {
			fmt.Println(err)
			return
		}
		return
	}

	err := templates.ExecuteTemplate(w, "home.tmpl", nil)
	if err != nil {
		fmt.Println(err)
	}
}

func checkAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := credentials{Name: "nouser", IsLoggedIn: false}
		ctx := context.WithValue(r.Context(), "credentials", user)
		token, err := r.Cookie("token")
		if err != nil {
			next.ServeHTTP(w, r.WithContext(ctx))
			fmt.Println(err)
			return
		}

		c, err := parseToken(token.Value)
		if err != nil {
			fmt.Println(err)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		c.IsLoggedIn = true
		ctx = renewToken(w, r, c)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// credentials are user credentials. For this example app we just have Name,
// IsLoggedIn, and the Token, but in production this could be expanded.
type credentials struct {
	Name       string `json:"username"`
	IsLoggedIn bool   `json:"isLoggedIn"`
	jwt.StandardClaims
}

// ckey/ctxkey is used as the key for the HTML context and is how we retrieve
// token information and pass it around to handlers
type ckey int

const (
	ctxkey ckey = iota
)

var (
	// connect to redis. Redis is used to store and retrieve user
	// credentials
	redisIP = os.Getenv("redisIP")
	client  = redis.NewClient(&redis.Options{
		Addr:     redisIP + ":6379",
		Password: "",
		DB:       0,
	})

	// I use templates as components and this line parses all my template
	// files in ./internal
	templates = template.Must(template.New("main").ParseGlob("internal/*/*.tmpl"))

	// hmacSampleSecret is used for creating the token
	hmacSampleSecret = []byte("0r9ck0r9cr09kcr09kcreiwn fwn f0ewf0ewncremcrecm")
)

// func main() {
// 	rs := client.Ping()
// 	str, err := rs.Result()
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	fmt.Println(str)

// 	rand.Seed(time.Now().UTC().UnixNano())

// 	mux := http.NewServeMux()
// 	mux.Handle("/", checkAuth(http.HandlerFunc(home)))
// 	mux.HandleFunc("/api/signup", signup)
// 	mux.HandleFunc("/api/signin", signin)
// 	mux.HandleFunc("/api/logout", logout)
// 	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("public"))))

// 	// Server configuration
// 	srv := &http.Server{
// 		// in production only ust SSL
// 		Addr:              ":8080",
// 		Handler:           mux,
// 		ReadHeaderTimeout: 5 * time.Second,
// 		WriteTimeout:      10 * time.Second,
// 		IdleTimeout:       5 * time.Second,
// 	}

// 	ctx, cancelCtx := context.WithCancel(context.Background())

// 	// Creating our server like this will allow us to allow more instances
// 	// at a later time
// 	go func() {
// 		err := srv.ListenAndServe()
// 		if errors.Is(err, http.ErrServerClosed) {
// 			fmt.Printf("server one closed\n")
// 		} else if err != nil {
// 			fmt.Printf("error listening for server one: %s\n", err)
// 		}
// 		cancelCtx()
// 	}()

// 	fmt.Println("Server started @ " + srv.Addr)
// 	<-ctx.Done()
// }

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func parseToken(tokenString string) (*credentials, error) {
	var claims *credentials
	token, err := jwt.ParseWithClaims(tokenString, &credentials{}, func(token *jwt.Token) (interface{}, error) {
		return hmacSampleSecret, nil
	})
	if err != nil {
		fmt.Println(err)
		cc := credentials{IsLoggedIn: false}
		return &cc, err
	}

	if claims, ok := token.Claims.(*credentials); ok && token.Valid {
		return claims, nil
	}
	return claims, err
}

func renewToken(w http.ResponseWriter, r *http.Request, claims *credentials) (ctx context.Context) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(hmacSampleSecret)
	if err != nil {
		fmt.Println(err)
	}

	expire := time.Now().Add(10 * time.Minute)
	cookie := http.Cookie{Name: "token", Value: ss, Path: "/", Expires: expire, MaxAge: 0}
	http.SetCookie(w, &cookie)

	client.Set(claims.Name+"token", ss, 0)
	ctx = context.WithValue(r.Context(), "credentials", claims)
	return
}

func setTokenCookie(w http.ResponseWriter, r *http.Request) (ctx context.Context) {
	claims := credentials{
		r.Form["username"][0],
		true,
		jwt.StandardClaims{
			// ExpiresAt: 15000,
			// Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(hmacSampleSecret)
	fmt.Printf("%v %v", ss, err)

	expire := time.Now().Add(10 * time.Minute)
	cookie := http.Cookie{Name: "token", Value: ss, Path: "/", Expires: expire, MaxAge: 0}
	http.SetCookie(w, &cookie)

	client.Set(r.Form["username"][0]+"token", ss, 0)
	ctx = context.WithValue(r.Context(), "credentials", claims)
	return
}
