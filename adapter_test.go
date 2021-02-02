// Copyright 2017 The casbin Authors. All Rights Reserved.
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
	"github.com/jackc/pgconn"
	"log"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()
	log.Print("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func initPolicy(t *testing.T, a *Adapter) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		panic(err)
	}

	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err = a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testSaveLoad(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.

	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func initAdapter(t *testing.T, driverName string, dataSourceName string, params ...interface{}) *Adapter {
	// Create an adapter
	a, err := NewAdapter(driverName, dataSourceName, params...)
	if err != nil {
		panic(err)
	}

	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

func initAdapterWithGormInstance(t *testing.T, db *gorm.DB) *Adapter {
	// Create an adapter
	a, _ := NewAdapterByDB(db)
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

func initAdapterWithGormInstanceAndCustomTable(t *testing.T, db *gorm.DB) *Adapter {
	type CasbinRule struct {
		ID    uint   `gorm:"primaryKey;autoIncrement"`
		Ptype string `gorm:"size:128;uniqueIndex:unique_index"`
		V0    string `gorm:"size:128;uniqueIndex:unique_index"`
		V1    string `gorm:"size:128;uniqueIndex:unique_index"`
		V2    string `gorm:"size:128;uniqueIndex:unique_index"`
		V3    string `gorm:"size:128;uniqueIndex:unique_index"`
		V4    string `gorm:"size:128;uniqueIndex:unique_index"`
		V5    string `gorm:"size:128;uniqueIndex:unique_index"`
	}

	// Create an adapter
	a, _ := NewAdapterByDBWithCustomTable(db, &CasbinRule{})
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

func initAdapterWithGormInstanceByName(t *testing.T, db *gorm.DB, name string) *Adapter {
	//Create an Adapter
	a, _ := NewAdapterByDBUseTableName(db, "", name)
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

//func TestNilField(t *testing.T) {
//	a, err := NewAdapter("sqlite3", "test.db")
//	assert.Nil(t, err)
//	defer os.Remove("test.db")
//
//	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
//	assert.Nil(t, err)
//	e.EnableAutoSave(false)
//
//	ok, err := e.AddPolicy("", "data1", "write")
//	assert.Nil(t, err)
//	e.SavePolicy()
//	assert.Nil(t, e.LoadPolicy())
//
//	ok, err = e.Enforce("", "data1", "write")
//	assert.Nil(t, err)
//	assert.Equal(t, ok, true)
//}

func testAutoSave(t *testing.T, a *Adapter) {

	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testFilteredPolicy(t *testing.T, a *Adapter) {
	// NewEnforcer() without an adapter will not auto load the policy
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")
	// Now set the adapter
	e.SetAdapter(a)

	// Load only alice's policies
	assert.Nil(t, e.LoadFilteredPolicy(Filter{V0: []string{"alice"}}))
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	// Load only bob's policies
	assert.Nil(t, e.LoadFilteredPolicy(Filter{V0: []string{"bob"}}))
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	// Load policies for data2_admin
	assert.Nil(t, e.LoadFilteredPolicy(Filter{V0: []string{"data2_admin"}}))
	testGetPolicy(t, e, [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Load policies for alice and bob
	assert.Nil(t, e.LoadFilteredPolicy(Filter{V0: []string{"alice", "bob"}}))
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testUpdatePolicy(t *testing.T, a *Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	e.EnableAutoSave(true)
	e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data1", "write"})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "write"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func TestAdapterWithCustomTable(t *testing.T) {
	db, err := gorm.Open(postgres.Open("user=postgres host=127.0.0.1 port=5432 sslmode=disable"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	if err = db.Exec("CREATE DATABASE casbin_custom_table").Error; err != nil {
		// 42P04 is	duplicate_database
		if err.(*pgconn.PgError).Code != "42P04" {
			panic(err)
		}
	}

	db, err = gorm.Open(postgres.Open("user=postgres host=127.0.0.1 port=5432 sslmode=disable dbname=casbin_custom_table"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a := initAdapterWithGormInstanceAndCustomTable(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstanceAndCustomTable(t, db)
	testFilteredPolicy(t, a)
}

func TestAdapters(t *testing.T) {
	a := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapter(t, "postgres", "user=postgres host=127.0.0.1 port=5432 sslmode=disable")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	db, err := gorm.Open(mysql.Open("root:@tcp(127.0.0.1:3306)/casbin"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	a = initAdapterWithGormInstance(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstance(t, db)
	testFilteredPolicy(t, a)

	db, err = gorm.Open(postgres.Open("user=postgres host=127.0.0.1 port=5432 sslmode=disable dbname=casbin"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	a = initAdapterWithGormInstance(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstance(t, db)
	testFilteredPolicy(t, a)

	db, err = gorm.Open(mysql.Open("root:@tcp(127.0.0.1:3306)/casbin"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	a = initAdapterWithGormInstanceByName(t, db, "casbin_rule")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstanceByName(t, db, "casbin_rule")
	testFilteredPolicy(t, a)

	db, err = gorm.Open(postgres.Open("user=postgres host=127.0.0.1 port=5432 sslmode=disable dbname=casbin"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	a = initAdapterWithGormInstanceByName(t, db, "casbin_rule")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstanceByName(t, db, "casbin_rule")
	testFilteredPolicy(t, a)

	a = initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")
	testUpdatePolicy(t, a)
}
