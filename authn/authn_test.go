package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/jaredhughes1012/bouncer"
)

func Test_getAuthToken(t *testing.T) {
	cases := []struct {
		name      string
		pattern   string
		headerVal string
		token     string
	}{
		{
			name:      "Bearer Match",
			pattern:   patternBearer,
			headerVal: "Bearer token",
			token:     "token",
		},
		{
			name:      "Bearer No Match",
			pattern:   patternBearer,
			headerVal: "Basic token",
			token:     "",
		},
		{
			name:      "Bearer No Header",
			pattern:   patternBearer,
			headerVal: "",
			token:     "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", c.headerVal)
			rr := regexp.MustCompile(c.pattern)

			token := getAuthToken(rr, r)
			if token != c.token {
				t.Errorf("%s failed: %s != %s", c.name, c.token, token)
			}
		})
	}
}

func Test_NewJwtMiddleware_NoFilter(t *testing.T) {
	type Identity struct{}

	cases := []struct {
		name       string
		secret     string
		authHeader string
		status     int
		filter     IdentityFilter
	}{
		{
			name:       "Happy Path",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA",
			secret:     "test",
			status:     http.StatusOK,
		},
		{
			name:       "Happy Path Custom Filter",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA",
			secret:     "test",
			status:     http.StatusOK,
			filter:     func(i bouncer.Identity) (interface{}, error) { return &Identity{}, nil },
		},
		{
			name:       "Custom Filter Validation Failed",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA",
			secret:     "test",
			status:     http.StatusUnauthorized,
			filter:     func(i bouncer.Identity) (interface{}, error) { return nil, errors.New("test") },
		},
		{
			name:       "Invalid Signature",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA",
			secret:     "test2",
			status:     http.StatusUnauthorized,
		},
		{
			name:       "No Auth",
			authHeader: "",
			secret:     "test",
			status:     http.StatusUnauthorized,
		},
		{
			name:       "Wrong Auth Type",
			authHeader: "Basic eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA",
			secret:     "test2",
			status:     http.StatusUnauthorized,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				idn := bouncer.GetIdentityCtx(r.Context())
				idnCustom := bouncer.GetCustomIdentityCtx[Identity](r.Context())

				if idn == nil {
					t.Error("No identity injected by middleware")
				} else if c.filter == nil && idnCustom != nil {
					t.Error("Custom identity injected without providing filter")
				} else if c.filter != nil && c.status == 200 && idnCustom == nil {
					t.Error("No custom identity injected by middleware")
				}

				w.WriteHeader(http.StatusOK)
			}

			middleware := NewJwtMiddleware([]byte(c.secret), c.filter)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", c.authHeader)

			middleware(http.HandlerFunc(handler)).ServeHTTP(w, r)

			if w.Result().StatusCode != c.status {
				t.Errorf("%d != %d", c.status, w.Result().StatusCode)
			}
		})
	}
}
