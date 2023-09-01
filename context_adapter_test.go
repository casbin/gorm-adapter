package gormadapter

import (
	"context"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
)

func mockExecuteWithContextTimeOut(ctx context.Context, fn func() error) error {
	done := make(chan error)
	go func() {
		time.Sleep(500 * time.Microsecond)
		done <- fn()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func clearDBPolicy() (*casbin.Enforcer, *ContextAdapter) {
	ca, err := NewContextAdapter("mysql", "root:root@tcp(127.0.0.1:3307)/", "casbin")
	if err != nil {
		panic(err)
	}
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", ca)
	if err != nil {
		panic(err)
	}
	e.ClearPolicy()
	_ = e.SavePolicy()

	return e, ca
}

func TestContextAdapter_LoadPolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	db, _ := openDBConnection("mysql", "root:@tcp(127.0.0.1:3307)/casbin")
	policy := &CasbinRule{
		Ptype: "p",
		V0:    "alice",
		V1:    "data1",
		V2:    "read",
	}
	db.Create(policy)

	assert.NoError(t, ca.LoadPolicyCtx(context.Background(), e.GetModel()))
	e, _ = casbin.NewEnforcer(e.GetModel(), ca)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.LoadPolicyCtx(ctx, e.GetModel()), "context deadline exceeded")
}

func TestContextAdapter_SavePolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	e.EnableAutoSave(false)
	_, _ = e.AddPolicy("alice", "data1", "read")
	assert.NoError(t, ca.SavePolicyCtx(context.Background(), e.GetModel()))
	_ = e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.SavePolicyCtx(ctx, e.GetModel()), "context deadline exceeded")
}

func TestContextAdapter_AddPolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	assert.NoError(t, ca.AddPolicyCtx(context.Background(), "p", "p", []string{"alice", "data1", "read"}))
	_ = e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.AddPolicyCtx(ctx, "p", "p", []string{"alice", "data1", "read"}), "context deadline exceeded")
}

func TestContextAdapter_RemovePolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	_ = ca.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	_ = ca.AddPolicy("p", "p", []string{"alice", "data2", "read"})
	assert.NoError(t, ca.RemovePolicyCtx(context.Background(), "p", "p", []string{"alice", "data1", "read"}))
	_ = e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data2", "read"}})

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.RemovePolicyCtx(ctx, "p", "p", []string{"alice", "data1", "read"}), "context deadline exceeded")
}

func TestContextAdapter_RemoveFilteredPolicyCtx(t *testing.T) {
	e, ca := clearDBPolicy()

	_ = ca.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	_ = ca.AddPolicy("p", "p", []string{"alice", "data1", "write"})
	_ = ca.AddPolicy("p", "p", []string{"alice", "data2", "read"})
	assert.NoError(t, ca.RemoveFilteredPolicyCtx(context.Background(), "p", "p", 1, "data1"))
	_ = e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data2", "read"}})

	var p = gomonkey.ApplyFunc(executeWithContext, mockExecuteWithContextTimeOut)
	defer p.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
	defer cancel()
	assert.EqualError(t, ca.RemoveFilteredPolicyCtx(ctx, "p", "p", 1, "data1"), "context deadline exceeded")
}
