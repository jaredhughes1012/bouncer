# Bouncer

Authentication (authn) and authorization (authz) framework for Go web services

## Install

```
go get -u github.com/jaredhughes1012/bouncer
```

## Authentication

Authentication is handled by the `authn` package. Use one of the authentication middlewares to automatically authenticate requests
and extract user identity. All authn middlewares can also use an optional filter to convert the built-in `bouncer` identity into
one tailored for your application

```
type SampleIdentity struct {
    Email string
}

func FilterIdentity(idn bouncer.Identity) (interface{}, error) {
    email := idn.GetString("email")
    if email == "" {
        return nil, errors.New("identity does not have required email")
    }

    return &SampleIdentity {
        Email: email,
    }, nil
}
```

If using an identity filter, you can still access the built-in bouncer identity as well. You can use different functions to retrieve both types

```
func handler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    idnBase := bouncer.GetIdentityCtx(ctx)
    idnCustom := bouncer.GetCustomIdentityCtx[SampleIdentity](ctx)
}
```

### JWT

```
func main() {
    mux := http.NewServeMux()

    secret := []byte("your secret here")
    middleware := authn.NewJwtMiddleware(secret, nil)
    // middleware := authn.NewJwtMiddleware(secret, *authn.JwtSigningMethodHMAC, FilterIdentity) /* For custom identity */
    handler := middleware(someHttpHandler)

    mux.Handle("/", handler)
    err := http.ListenAndServe(":8080", mux)
    log.Fatal(err)
}
```

## Authorization

Authorization is handled by the `authz` package. Authorization is implemented by custom authorization handlers provided to `authz` middleware. Can use
built in bouncer identity or custom identity. Middleware must be used after `authn` middleware to have access to identity.

If an authz filter returns an error, the request will be short-circuited and the client will receive a 403 - Forbidden response

### Built in

```

func adminFilter(ctx context.Context, idn bouncer.Identity) error {
    role := idn.GetString("role")
    if role != "admin" {
        return errors.New("User is not an admin")
    }

    return null
}

func main() {
    mux := http.NewServeMux()

    secret := []byte("your secret here")
    authnMiddleware := authn.NewJwtMiddleware(secret, nil)
    authzMiddleware := authz.NewMiddleware(adminFilter)

    handler := authzMiddleware(authnMiddleware(someHttpHandler))

    mux.Handle("/", handler)
    err := http.ListenAndServe(":8080", mux)
    log.Fatal(err)
}

```

### Custom

```
type SampleIdentity struct {
    Role string
}

func FilterIdentity(idn bouncer.Identity) (interface{}, error) {
    role := idn.GetString("role")
    if role == "" {
        return nil, errors.New("identity does not have required role")
    }

    return &SampleIdentity {
        Role: role,
    }, nil
}

func adminFilter(ctx context.Context, idn SampleIdentity) error {
    if idn.Role != "admin" {
        return errors.New("User is not an admin")
    }

    return null
}

func main() {
    mux := http.NewServeMux()

    secret := []byte("your secret here")
    authnMiddleware := authn.NewJwtMiddleware(secret, FilterIdentity)
    authzMiddleware := authz.NewCustomMiddleware[SampleIdentity](adminFilter)

    handler := authzMiddleware(authnMiddleware(someHttpHandler))

    mux.Handle("/", handler)
    err := http.ListenAndServe(":8080", mux)
    log.Fatal(err)
}

```