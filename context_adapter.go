// Copyright 2023 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gormadapter

import (
	"context"

	"github.com/casbin/casbin/v2/model"
)

type ContextAdapter struct {
	*Adapter
}

func NewContextAdapter(driverName string, dataSourceName string, params ...interface{}) (*ContextAdapter, error) {
	a, err := NewAdapter(driverName, dataSourceName, params...)
	return &ContextAdapter{
		a,
	}, err
}

// executeWithContext is a helper function to execute a function with context and return the result or error.
func executeWithContext(ctx context.Context, fn func() error) error {
	done := make(chan error)
	go func() {
		done <- fn()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// LoadPolicyCtx loads all policy rules from the storage with context.
func (ca *ContextAdapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	return executeWithContext(ctx, func() error {
		return ca.LoadPolicy(model)
	})
}

// SavePolicyCtx saves all policy rules to the storage with context.
func (ca *ContextAdapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	return executeWithContext(ctx, func() error {
		return ca.SavePolicy(model)
	})
}

// AddPolicyCtx adds a policy rule to the storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return executeWithContext(ctx, func() error {
		return ca.AddPolicy(sec, ptype, rule)
	})
}

// RemovePolicyCtx removes a policy rule from the storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return executeWithContext(ctx, func() error {
		return ca.RemovePolicy(sec, ptype, rule)
	})
}

// RemoveFilteredPolicyCtx removes policy rules that match the filter from the storage with context.
// This is part of the Auto-Save feature.
func (ca *ContextAdapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return executeWithContext(ctx, func() error {
		return ca.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	})
}
