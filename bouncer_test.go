package bouncer

import (
	"context"
	"testing"
)

func Test_Identity_GetString(t *testing.T) {
	cases := []struct {
		name string
		key1 string
		key2 string
		val1 string
		val2 string
	}{
		{
			name: "Happy Path",
			key1: "key1",
			key2: "key1",
			val1: "val1",
			val2: "val1",
		},
		{
			name: "Key does not exist",
			key1: "key1",
			key2: "key2",
			val1: "val1",
			val2: "",
		},
		{
			name: "Key exists but is empty",
			key1: "key1",
			key2: "key1",
			val1: "",
			val2: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idn := make(Identity)
			idn[c.key1] = c.val1

			v := idn.GetString(c.key2)
			if v != c.val2 {
				t.Errorf("%s-%s failed: %s != %s", c.key1, c.key2, v, c.val2)
			}
		})
	}
}

func Test_GetIdentityCtx(t *testing.T) {
	idn1 := make(Identity)
	idn1["test"] = "val"

	ctx := context.WithValue(context.Background(), ctxKeyIdn, &idn1)
	idn2 := GetIdentityCtx(ctx)

	v1, v2 := idn1["test"], (*idn2)["test"]
	if v1 != v2 {
		t.Errorf("%s != %s", v1, v2)
	}
}

func Test_GetIdentityCtx_NoIdentity(t *testing.T) {
	ctx := context.Background()
	idn := GetIdentityCtx(ctx)

	if idn != nil {
		t.Errorf("Unexpected value %v found", idn)
	}
}

func Test_GetCustomIdentityCtx(t *testing.T) {
	type Identity struct {
		Test string
	}
	idn1 := Identity{
		Test: "val",
	}

	ctx := context.WithValue(context.Background(), ctxKeyCustom, &idn1)
	idn2 := GetCustomIdentityCtx[Identity](ctx)

	if idn1.Test != idn2.Test {
		t.Errorf("%s != %s", idn1.Test, idn2.Test)
	}
}

func Test_GetCustomIdentityCtx_NoIdentity(t *testing.T) {
	type Identity struct {
		Test string
	}

	ctx := context.Background()
	idn := GetCustomIdentityCtx[Identity](ctx)

	if idn != nil {
		t.Errorf("Unexpected value %v found", idn)
	}
}

func Test_InjectIdentityCtx(t *testing.T) {
	idn := make(Identity)
	idn["test"] = "val"

	ctx := context.Background()
	ctx = InjectIdentityCtx(ctx, idn)

	idn2, ok := ctx.Value(ctxKeyIdn).(*Identity)
	if !ok {
		t.Error("Identity not injected")
	} else if idn["test"].(string) != (*idn2)["test"].(string) {
		t.Error("Incorrect identity")
	}
}
func Test_InjectIdentityCtx_Nil(t *testing.T) {
	ctx := context.Background()
	ctx = InjectIdentityCtx(ctx, nil)

	_, ok := ctx.Value(ctxKeyIdn).(*Identity)
	if ok {
		t.Error("Identity injected")
	}
}

func Test_InjectCustomIdentityCtx(t *testing.T) {
	type Identity struct {
		Test string
	}

	idn := Identity{Test: "val"}

	ctx := context.Background()
	ctx = InjectCustomIdentityCtx(ctx, &idn)

	idn2, ok := ctx.Value(ctxKeyCustom).(*Identity)

	if !ok {
		t.Error("Identity not injected")
	} else if idn.Test != idn2.Test {
		t.Error("Incorrect identity")
	}
}
