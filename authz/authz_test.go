package authz

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jaredhughes1012/bouncer"
)

func Test_NewMiddleware(t *testing.T) {
	cases := []struct {
		name   string
		filter Filter
		status int
		idn    bouncer.Identity
	}{
		{
			name:   "No Error",
			filter: func(idn bouncer.Identity) error { return nil },
			status: http.StatusOK,
			idn:    make(bouncer.Identity),
		},
		{
			name:   "No Identity",
			filter: func(idn bouncer.Identity) error { return nil },
			status: http.StatusUnauthorized,
			idn:    nil,
		},
		{
			name:   "Error",
			filter: func(idn bouncer.Identity) error { return errors.New("test") },
			status: http.StatusForbidden,
			idn:    make(bouncer.Identity),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}

			middleware := NewMiddleware(c.filter)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = r.WithContext(bouncer.InjectIdentityCtx(r.Context(), c.idn))

			middleware(http.HandlerFunc(handler)).ServeHTTP(w, r)
		})
	}
}

func Test_NewCustomMiddleware(t *testing.T) {
	type Identity struct{}

	cases := []struct {
		name   string
		filter CustomFilter[Identity]
		status int
		idn    *Identity
	}{
		{
			name:   "No Error",
			filter: func(idn Identity) error { return nil },
			status: http.StatusOK,
			idn:    &Identity{},
		},
		{
			name:   "No Identity",
			filter: func(idn Identity) error { return nil },
			status: http.StatusUnauthorized,
		},
		{
			name:   "Error",
			filter: func(idn Identity) error { return errors.New("test") },
			status: http.StatusForbidden,
			idn:    &Identity{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}

			middleware := NewCustomMiddleware(c.filter)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = r.WithContext(bouncer.InjectCustomIdentityCtx(r.Context(), c.idn))

			middleware(http.HandlerFunc(handler)).ServeHTTP(w, r)
		})
	}
}
