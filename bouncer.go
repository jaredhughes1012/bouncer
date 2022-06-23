package bouncer

import (
	"context"
	"net/http"
)

type ctxKey string

// Collection of non-sensitive data related to the user
type Identity map[string]interface{}

// Function that handles an intermediate step between an http request being received and an http handler running or
// an an http handler finishing and an http response being written
type Middleware func(http.Handler) http.Handler

var (
	ctxKeyIdn    ctxKey = "bouncer.ctx.idn"
	ctxKeyCustom ctxKey = "bouncer.ctx.custom"
)

// Gets a string value from this identity
func (idn Identity) GetString(key string) string {
	v, ok := idn[key].(string)
	if !ok {
		return ""
	}

	return v
}

// Injects an identity into a new context based off the given context
func InjectIdentityCtx(ctx context.Context, idn Identity) context.Context {
	if idn != nil {
		return context.WithValue(ctx, ctxKeyIdn, &idn)
	} else {
		return ctx
	}
}

// Injects a custom identity into a new context based off the given context
func InjectCustomIdentityCtx(ctx context.Context, idn any) context.Context {
	return context.WithValue(ctx, ctxKeyCustom, idn)
}

// Gets identity injected into HTTP context by an authn middleware
func GetIdentityCtx(ctx context.Context) *Identity {
	if idn, ok := ctx.Value(ctxKeyIdn).(*Identity); !ok {
		return nil
	} else {
		return idn
	}
}

// Gets identity injected into HTTP context by an authn middleware and filtered into a custom type by an auth filter
func GetCustomIdentityCtx[T any](ctx context.Context) *T {
	if idn, ok := ctx.Value(ctxKeyCustom).(*T); !ok {
		return nil
	} else {
		return idn
	}
}
