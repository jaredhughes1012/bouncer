package authz

import (
	"net/http"

	"github.com/jaredhughes1012/bouncer"
)

// Authorization filters check that the user with the given identity is able to access the
// endpoint being executed. Return an error to prevent the endpoint from running and return
// a Forbidden (403) response
type Filter func(idn bouncer.Identity) error

// Custom authorization filters check that the user with the given identity (represented by
// a custom type) is able to access the endpoint being executed. Return an error to prevent
// the endpoint from running and return a Forbidden (403) response
type CustomFilter[T any] func(idn T) error

// Creates a new middleware that executes the given authorization filter on all http requests
func NewMiddleware(filter Filter) bouncer.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			idn := bouncer.GetIdentityCtx(ctx)
			if idn == nil {
				http.Error(w, "Failed to access identity, please log in again", http.StatusUnauthorized)
				return
			}

			err := filter(*idn)

			if err != nil {
				http.Error(w, "You are not authorized to access this resource", http.StatusForbidden)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// Creates a new middleware that executes the given custom authorization filter on all http requests
func NewCustomMiddleware[T any](filter CustomFilter[T]) bouncer.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			idn := bouncer.GetCustomIdentityCtx[T](ctx)
			if idn == nil {
				http.Error(w, "Failed to access identity, please log in again", http.StatusUnauthorized)
				return
			}

			err := filter(*idn)

			if err != nil {
				http.Error(w, "You are not authorized to access this resource", http.StatusForbidden)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
