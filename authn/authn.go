package authn

import (
	"net/http"
	"regexp"

	"github.com/golang-jwt/jwt"
	"github.com/jaredhughes1012/bouncer"
)

// Filter that converts bouncer's dynamically typed Identity into another identity
// object. This will be mapped as bouncer's custom identity and exists in context
// alongside the default identity
type IdentityFilter func(bouncer.Identity) (interface{}, error)

const (
	patternBearer = "Bearer (.*)"
)

func getAuthToken(regex *regexp.Regexp, r *http.Request) string {
	match := regex.FindStringSubmatch(r.Header.Get("Authorization"))
	if len(match) >= 2 {
		return match[1]
	}

	return ""
}

// Creates a new authentication middleware that uses JWT bearer tokens for authentication. Filter is optional for converting
// the built in identity into a custom identity
func NewJwtMiddleware(secret []byte, filter IdentityFilter) bouncer.Middleware {
	rr := regexp.MustCompile(patternBearer)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tStr := getAuthToken(rr, r)
			if tStr == "" {
				http.Error(w, "Invalid or missing Authorization", http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse(tStr, func(token *jwt.Token) (interface{}, error) {
				return secret, nil
			})

			if err != nil {
				http.Error(w, "Invalid Authorization token", http.StatusUnauthorized)
			} else if claims, ok := token.Claims.(jwt.MapClaims); !ok {
				http.Error(w, "Invalid Authorization claims", http.StatusUnauthorized)
			} else {
				idn := bouncer.Identity(claims)
				r = r.WithContext(bouncer.InjectIdentityCtx(r.Context(), idn))

				if filter != nil {
					idnCustom, err := filter(idn)
					if err != nil {
						http.Error(w, "Identity State Invalid", http.StatusUnauthorized)
					}

					r = r.WithContext(bouncer.InjectCustomIdentityCtx(r.Context(), idnCustom))
				}

				next.ServeHTTP(w, r)
			}
		})
	}
}
