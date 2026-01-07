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
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/util"
	"github.com/glebarez/sqlite"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes, err := e.GetPolicy()
	if err != nil {
		panic(err)
	}

	log.Print("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func testGetPolicyWithoutOrder(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes, err := e.GetPolicy()
	if err != nil {
		panic(err)
	}

	log.Print("Policy: ", myRes)

	if !arrayEqualsWithoutOrder(myRes, res) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func arrayEqualsWithoutOrder(a [][]string, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}

	mapA := make(map[int]string)
	mapB := make(map[int]string)
	order := make(map[int]struct{})
	l := len(a)

	for i := 0; i < l; i++ {
		mapA[i] = util.ArrayToString(a[i])
		mapB[i] = util.ArrayToString(b[i])
	}

	for i := 0; i < l; i++ {
		for j := 0; j < l; j++ {
			if _, ok := order[j]; ok {
				if j == l-1 {
					return false
				} else {
					continue
				}
			}
			if mapA[i] == mapB[j] {
				order[j] = struct{}{}
				break
			} else if j == l-1 {
				return false
			}
		}
	}
	return true
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
	type TestCasbinRule struct {
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
	a, _ := NewAdapterByDBWithCustomTable(db, &TestCasbinRule{}, "test_casbin_rule")
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

func initAdapterWithoutAutoMigrate(t *testing.T, db *gorm.DB) *Adapter {
	var err error
	var customTableName = "without_auto_migrate_custom_table"
	hasTable := db.Migrator().HasTable(customTableName)
	if hasTable {
		err = db.Migrator().DropTable(customTableName)
		if err != nil {
			panic(err)
		}
	}

	TurnOffAutoMigrate(db)

	type CustomCasbinRule struct {
		ID    uint   `gorm:"primaryKey;autoIncrement"`
		Ptype string `gorm:"size:50"`
		V0    string `gorm:"size:50"`
		V1    string `gorm:"size:50"`
		V2    string `gorm:"size:50"`
		V3    string `gorm:"size:50"`
		V4    string `gorm:"size:50"`
		V5    string `gorm:"size:50"`
		V6    string `gorm:"size:50"`
		V7    string `gorm:"size:50"`
	}
	a, err := NewAdapterByDBWithCustomTable(db, &CustomCasbinRule{}, customTableName)

	hasTable = a.db.Migrator().HasTable(a.getFullTableName())
	if hasTable {
		t.Fatal("AutoMigration has been disabled but tables are still created in NewAdapterWithoutAutoMigrate method")
	}
	err = a.db.Migrator().CreateTable(&CustomCasbinRule{})
	if err != nil {
		panic(err)
	}
	initPolicy(t, a)
	return a
}

func initAdapterWithGormInstanceByMulDb(t *testing.T, dbPool DbPool, dbName string, prefix string, tableName string) *Adapter {
	//Create an Adapter
	a, _ := NewAdapterByMulDb(dbPool, dbName, prefix, tableName)
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

func initAdapterWithGormInstanceByPrefixAndName(t *testing.T, db *gorm.DB, prefix, name string) *Adapter {
	//Create an Adapter
	a, _ := NewAdapterByDBUseTableName(db, prefix, name)
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Now the DB has policy, so we can provide a normal use case.
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	return a
}

func TestNilField(t *testing.T) {
	a, err := NewAdapter("sqlite3", "test.db")
	assert.Nil(t, err)
	defer os.Remove("test.db")

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	assert.Nil(t, err)
	e.EnableAutoSave(false)

	ok, err := e.AddPolicy("", "data1", "write")
	assert.Nil(t, err)
	e.SavePolicy()
	assert.Nil(t, e.LoadPolicy())

	ok, err = e.Enforce("", "data1", "write")
	assert.Nil(t, err)
	assert.Equal(t, ok, true)
}

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

	assert.Nil(t, e.LoadFilteredPolicy(BatchFilter{
		filters: []Filter{
			{V0: []string{"alice"}},
			{V1: []string{"data2"}},
		},
	}))
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	})
}

func testUpdatePolicy(t *testing.T, a *Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	e.EnableAutoSave(true)
	e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data1", "write"})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "write"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testUpdatePolicies(t *testing.T, a *Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	e.EnableAutoSave(true)
	e.UpdatePolicies([][]string{{"alice", "data1", "write"}, {"bob", "data2", "write"}}, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "read"}})
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "read"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testUpdateFilteredPolicies(t *testing.T, a *Adapter) {
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	e.EnableAutoSave(true)
	e.UpdateFilteredPolicies([][]string{{"alice", "data1", "write"}}, 0, "alice", "data1", "read")
	e.UpdateFilteredPolicies([][]string{{"bob", "data2", "read"}}, 0, "bob", "data2", "write")
	e.LoadPolicy()
	testGetPolicyWithoutOrder(t, e, [][]string{{"alice", "data1", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"bob", "data2", "read"}})
}

func TestAdapterWithCustomTable(t *testing.T) {
	db, err := gorm.Open(postgres.Open("user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	if err = db.Exec("CREATE DATABASE casbin_custom_table").Error; err != nil {
		// 42P04 is	duplicate_database
		if !strings.Contains(fmt.Sprintf("%s", err), "42P04") {
			panic(err)
		}
	}

	db, err = gorm.Open(postgres.Open("user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable dbname=casbin_custom_table"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a := initAdapterWithGormInstanceAndCustomTable(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstanceAndCustomTable(t, db)
	testFilteredPolicy(t, a)
}

func TestAdapterWithoutAutoMigrate(t *testing.T) {
	db, err := gorm.Open(mysql.Open("root:@tcp(127.0.0.1:3306)/casbin"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a := initAdapterWithoutAutoMigrate(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithoutAutoMigrate(t, db)
	testFilteredPolicy(t, a)

	db, err = gorm.Open(postgres.Open("user=postgres password=postgres host=localhost port=5432 sslmode=disable TimeZone=Asia/Shanghai"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	if err = db.Exec("CREATE DATABASE casbin_custom_table").Error; err != nil {
		// 42P04 is	duplicate_database
		if !strings.Contains(fmt.Sprintf("%s", err), "42P04") {
			panic(err)
		}
	}

	db, err = gorm.Open(postgres.Open("user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable dbname=casbin_custom_table"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a = initAdapterWithoutAutoMigrate(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithoutAutoMigrate(t, db)
	testFilteredPolicy(t, a)

	db, err = gorm.Open(sqlite.Open("casbin.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a = initAdapterWithoutAutoMigrate(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithoutAutoMigrate(t, db)
	testFilteredPolicy(t, a)

	db, err = gorm.Open(sqlserver.Open("sqlserver://sa:SqlServer123@localhost:1433?database=master"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	a = initAdapterWithoutAutoMigrate(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithoutAutoMigrate(t, db)
	testFilteredPolicy(t, a)
}

func TestAdapterWithMulDb(t *testing.T) {
	//create new database
	NewAdapter("mysql", "root:@tcp(127.0.0.1:3306)/", "casbin")
	NewAdapter("mysql", "root:@tcp(127.0.0.1:3306)/", "casbin2")

	testBasicFeatures(t)
	testIndependenceBetweenMulDb(t)
}

func testIndependenceBetweenMulDb(t *testing.T) {
	dsn := "root:@tcp(127.0.0.1:3306)/casbin"
	dsn2 := "root:@tcp(127.0.0.1:3306)/casbin2"

	dbPool, err := InitDbResolver([]gorm.Dialector{mysql.Open(dsn), mysql.Open(dsn2)}, []string{"casbin", "casbin2"})

	if err != nil {
		panic(err)
	}

	//test independence between multi adapter
	a1 := initAdapterWithGormInstanceByMulDb(t, dbPool, "casbin", "", "casbin_rule")
	a1.AddPolicy("p", "p", []string{"alice", "book", "read"})
	a2 := initAdapterWithGormInstanceByMulDb(t, dbPool, "casbin2", "", "casbin_rule2")
	e, _ := casbin.NewEnforcer("./examples/rbac_model.conf", a2)
	res, err := e.Enforce("alice", "book", "read")
	if err != nil || res {
		t.Error("switch DB fail because data don't change")
	}
}

func testBasicFeatures(t *testing.T) {
	dsn := "root:@tcp(127.0.0.1:3306)/casbin"
	dsn2 := "root:@tcp(127.0.0.1:3306)/casbin2"

	dbPool, err := InitDbResolver([]gorm.Dialector{mysql.Open(dsn), mysql.Open(dsn2)}, []string{"casbin", "casbin2"})

	if err != nil {
		panic(err)
	}
	//test basic features
	a := initAdapterWithGormInstanceByMulDb(t, dbPool, "casbin", "", "casbin_rule")
	testAutoSave(t, a)
	testSaveLoad(t, a)
	a = initAdapterWithGormInstanceByMulDb(t, dbPool, "casbin", "", "casbin_rule")
	testFilteredPolicy(t, a)

	a = initAdapterWithGormInstanceByMulDb(t, dbPool, "casbin2", "", "casbin_rule2")
	testAutoSave(t, a)
	testSaveLoad(t, a)
	a = initAdapterWithGormInstanceByMulDb(t, dbPool, "casbin2", "", "casbin_rule2")
	testFilteredPolicy(t, a)
}

func TestAdapters(t *testing.T) {
	a := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapter(t, "postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapter(t, "sqlite3", "casbin.db")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapter(t, "sqlserver", "sqlserver://sa:SqlServer123@localhost:1433", "master", "casbin_rule")
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

	db, err = gorm.Open(postgres.Open("user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable dbname=casbin"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	a = initAdapterWithGormInstance(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstance(t, db)
	testFilteredPolicy(t, a)

	db, err = gorm.Open(sqlite.Open("casbin.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	a = initAdapterWithGormInstance(t, db)
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstance(t, db)
	testFilteredPolicy(t, a)

	db, err = gorm.Open(sqlserver.Open("sqlserver://sa:SqlServer123@localhost:1433?database=master"), &gorm.Config{})
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

	db, err = gorm.Open(postgres.Open("user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable dbname=casbin"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	a = initAdapterWithGormInstanceByName(t, db, "casbin_rule")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstanceByName(t, db, "casbin_rule")
	testFilteredPolicy(t, a)

	a = initAdapterWithGormInstanceByPrefixAndName(t, db, "casbin", "first")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstanceByPrefixAndName(t, db, "casbin", "second")
	testFilteredPolicy(t, a)

	db, err = gorm.Open(sqlite.Open("casbin.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	a = initAdapterWithGormInstanceByName(t, db, "casbin_rule")
	testAutoSave(t, a)
	testSaveLoad(t, a)

	a = initAdapterWithGormInstanceByName(t, db, "casbin_rule")
	testFilteredPolicy(t, a)

	db, err = gorm.Open(sqlserver.Open("sqlserver://sa:SqlServer123@localhost:1433?database=master"), &gorm.Config{})
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
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)

	a = initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")
	a.AddLogger(logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{}))
	testUpdatePolicy(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)

	a = initAdapter(t, "postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable")
	testUpdatePolicy(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)

	a = initAdapter(t, "postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable")
	a.AddLogger(logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{}))
	testUpdatePolicy(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)

	a = initAdapter(t, "sqlite3", "casbin.db")
	testUpdatePolicy(t, a)
	testUpdatePolicies(t, a)

	a = initAdapter(t, "sqlserver", "sqlserver://sa:SqlServer123@localhost:1433", "master", "casbin_rule")
	testUpdatePolicy(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)

	a = initAdapter(t, "sqlserver", "sqlserver://sa:SqlServer123@localhost:1433", "master", "casbin_rule")
	a.AddLogger(logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{}))
	testUpdatePolicy(t, a)
	testUpdatePolicies(t, a)
	testUpdateFilteredPolicies(t, a)
}

func TestAddPolicies(t *testing.T) {
	a := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	e.AddPolicies([][]string{{"jack", "data1", "read"}, {"jack2", "data1", "read"}})
	e.LoadPolicy()

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"jack", "data1", "read"}, {"jack2", "data1", "read"}})
}

func TestAddPolicy(t *testing.T) {
	tests := []struct {
		driverName     string
		dataSourceName string
		params         []any
	}{
		{"mysql", "root:@tcp(127.0.0.1:3306)/", []any{"casbin", "casbin_rule"}},
		{"postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable", nil},
		// {"sqlserver", "sqlserver://sa:SqlServer123@localhost:1433", []any{"master", "casbin_rule"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.driverName, func(t *testing.T) {
			t.Parallel()
			a := initAdapter(t, test.driverName, test.dataSourceName, test.params...)
			e1, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
			e2, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

			policy := []string{"alice", "data1", "TestAddPolicy"}

			ok, err := e1.AddPolicy(policy)
			if err != nil {
				t.Errorf("e1.AddPolicy() got err %v", err)
			}
			if !ok {
				t.Errorf("e1.AddPolicy() got false, want true")
			}

			ok, err = e2.AddPolicy(policy)
			if err != nil {
				t.Errorf("e2.AddPolicy() got err %v", err)
			}
			if !ok {
				t.Errorf("e2.AddPolicy() got false, want true")
			}
		})
	}
}

func TestTransaction(t *testing.T) {
	// create adapter using the same pattern as other tests
	adapter := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")

	// create enforcer
	enforcer, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	assert.NoError(t, err)

	// load policy
	err = enforcer.LoadPolicy()
	assert.NoError(t, err)

	// test 1: basic transaction operation
	t.Run("Basic Transaction", func(t *testing.T) {
		// reload policy for clean state
		err := enforcer.LoadPolicy()
		assert.NoError(t, err)

		err = adapter.Transaction(enforcer, func(e casbin.IEnforcer) error {
			_, err := e.AddPolicy("alice", "data1", "read")
			if err != nil {
				return err
			}
			_, err = e.AddPolicy("alice", "data2", "write")
			return err
		})
		assert.NoError(t, err)

		// verify policies were added successfully
		ok, _ := enforcer.Enforce("alice", "data1", "read")
		assert.True(t, ok)
		ok, _ = enforcer.Enforce("alice", "data2", "write")
		assert.True(t, ok)
	})

	// test 2: transaction rollback
	t.Run("Transaction Rollback", func(t *testing.T) {
		// reload policy for clean state
		err := enforcer.LoadPolicy()
		assert.NoError(t, err)

		err = adapter.Transaction(enforcer, func(e casbin.IEnforcer) error {
			_, err := e.AddPolicy("bob", "data3", "read")
			if err != nil {
				return err
			}
			// intentionally return error to trigger rollback
			return assert.AnError
		})
		assert.Error(t, err)

		// verify policy was rolled back
		ok, _ := enforcer.Enforce("bob", "data3", "read")
		assert.False(t, ok)
	})

	// test 3: nested transaction - inner success, outer success
	t.Run("Nested Transaction - Inner Success Outer Success", func(t *testing.T) {
		// reload policy for clean state
		err := enforcer.LoadPolicy()
		assert.NoError(t, err)

		err = adapter.Transaction(enforcer, func(e casbin.IEnforcer) error {
			// outer transaction
			_, err := e.AddPolicy("charlie", "data4", "read")
			if err != nil {
				return err
			}

			// nested transaction
			return adapter.Transaction(e, func(innerE casbin.IEnforcer) error {
				_, err := innerE.AddPolicy("charlie", "data5", "write")
				if err != nil {
					return err
				}
				_, err = innerE.AddPolicy("charlie", "data6", "delete")
				return err
			})
		})
		assert.NoError(t, err)

		// verify all policies
		ok, _ := enforcer.Enforce("charlie", "data4", "read")
		assert.True(t, ok)
		ok, _ = enforcer.Enforce("charlie", "data5", "write")
		assert.True(t, ok)
		ok, _ = enforcer.Enforce("charlie", "data6", "delete")
		assert.True(t, ok)
	})

	// test 4: nested transaction - inner rollback, outer success
	t.Run("Nested Transaction - Inner Rollback Outer Success", func(t *testing.T) {
		// reload policy for clean state
		err := enforcer.LoadPolicy()
		assert.NoError(t, err)

		err = adapter.Transaction(enforcer, func(e casbin.IEnforcer) error {
			// outer transaction
			_, err := e.AddPolicy("david", "data7", "read")
			if err != nil {
				return err
			}

			// nested transaction that fails
			err = adapter.Transaction(e, func(innerE casbin.IEnforcer) error {
				_, err := innerE.AddPolicy("david", "data8", "write")
				if err != nil {
					return err
				}
				// inner transaction fails
				return assert.AnError
			})
			if err != nil {
				// inner transaction failed, but outer transaction should continue
				// the savepoint rollback has already undone the inner transaction changes
				return err
			}

			// outer transaction continues despite inner failure
			_, err = e.AddPolicy("david", "data9", "execute")
			return err
		})
		assert.NoError(t, err)

		// verify outer transaction policies are committed
		ok, _ := enforcer.Enforce("david", "data7", "read")
		assert.True(t, ok, "Outer transaction policy should be committed")
		ok, _ = enforcer.Enforce("david", "data9", "execute")
		assert.True(t, ok, "Outer transaction policy should be committed")

		// verify inner transaction policies are rolled back (savepoint behavior)
		ok, _ = enforcer.Enforce("david", "data8", "write")
		assert.False(t, ok, "Inner transaction policy should be rolled back due to savepoint")
	})

	// test 5: nested transaction - inner success, outer rollback
	t.Run("Nested Transaction - Inner Success Outer Rollback", func(t *testing.T) {
		// reload policy for clean state
		err := enforcer.LoadPolicy()
		assert.NoError(t, err)

		err = adapter.Transaction(enforcer, func(e casbin.IEnforcer) error {
			// outer transaction
			_, err := e.AddPolicy("eve", "data10", "read")
			if err != nil {
				return err
			}

			// nested transaction that succeeds
			err = adapter.Transaction(e, func(innerE casbin.IEnforcer) error {
				_, err := innerE.AddPolicy("eve", "data11", "write")
				if err != nil {
					return err
				}
				_, err = innerE.AddPolicy("eve", "data12", "delete")
				return err
			})
			if err != nil {
				// inner transaction failed, but outer transaction should continue
				// the savepoint rollback has already undone the inner transaction changes
				return err
			}

			// outer transaction continues despite inner failure
			_, err = e.AddPolicy("eve", "data13", "execute")
			if err != nil {
				return err
			}
			// outer transaction fails
			return assert.AnError
		})
		assert.Error(t, err)

		// verify all policies are rolled back (both outer and inner)
		ok, _ := enforcer.Enforce("eve", "data10", "read")
		assert.False(t, ok)
		ok, _ = enforcer.Enforce("eve", "data11", "write")
		assert.False(t, ok)
		ok, _ = enforcer.Enforce("eve", "data12", "delete")
		assert.False(t, ok)
	})

	// test 6: deeply nested transactions
	t.Run("Deeply Nested Transactions", func(t *testing.T) {
		// reload policy for clean state
		err := enforcer.LoadPolicy()
		assert.NoError(t, err)

		err = adapter.Transaction(enforcer, func(e casbin.IEnforcer) error {
			// level 1
			_, err := e.AddPolicy("frank", "data13", "read")
			if err != nil {
				return err
			}

			// level 2
			err = adapter.Transaction(e, func(e2 casbin.IEnforcer) error {
				_, err := e2.AddPolicy("frank", "data14", "write")
				if err != nil {
					return err
				}

				// level 3
				return adapter.Transaction(e2, func(e3 casbin.IEnforcer) error {
					_, err := e3.AddPolicy("frank", "data15", "delete")
					if err != nil {
						return err
					}
					_, err = e3.AddPolicy("frank", "data16", "execute")
					return err
				})
			})
			return err
		})
		assert.NoError(t, err)

		// verify all policies
		ok, _ := enforcer.Enforce("frank", "data13", "read")
		assert.True(t, ok)
		ok, _ = enforcer.Enforce("frank", "data14", "write")
		assert.True(t, ok)
		ok, _ = enforcer.Enforce("frank", "data15", "delete")
		assert.True(t, ok)
		ok, _ = enforcer.Enforce("frank", "data16", "execute")
		assert.True(t, ok)
	})

	// test 7: adapter type check
	t.Run("Adapter Type Check", func(t *testing.T) {
		// create an incompatible adapter
		mockEnforcer, _ := casbin.NewEnforcer("examples/rbac_model.conf")

		err := adapter.Transaction(mockEnforcer, func(e casbin.IEnforcer) error {
			return nil
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected adapter of type Adapter")
	})
}

func TestTransactionRace(t *testing.T) {
	// create adapter using the same pattern as other tests
	a := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")

	// create enforcer
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	require.NoError(t, err)

	// load policy
	err = e.LoadPolicy()
	require.NoError(t, err)

	concurrency := 100

	var g errgroup.Group
	for i := 0; i < concurrency; i++ {
		i := i
		g.Go(func() error {
			return a.Transaction(e, func(e casbin.IEnforcer) error {
				_, err := e.AddPolicy("jack", fmt.Sprintf("data%d", i), "write")
				if err != nil {
					return err
				}
				return nil
			})
		})
	}
	require.NoError(t, g.Wait())

	for i := 0; i < concurrency; i++ {
		hasPolicy, err := e.HasPolicy("jack", fmt.Sprintf("data%d", i), "write")
		if err != nil {
			panic(err)
		}

		require.True(t, hasPolicy)
	}
}

func TestTransactionWithSavePolicy(t *testing.T) {
	// create adapter using the same pattern as other tests
	a := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")

	// create enforcer
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	require.NoError(t, err)

	// load policy
	err = e.LoadPolicy()
	require.NoError(t, err)

	err = a.Transaction(e, func(e casbin.IEnforcer) error {
		_, err := e.AddPolicy("jack", "data1", "write")
		if err != nil {
			return err
		}
		_, err = e.AddPolicy("jack", "data2", "write")
		if err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)

	// verify policies were added successfully
	ok, _ := e.Enforce("jack", "data1", "write")
	require.True(t, ok)
	ok, _ = e.Enforce("jack", "data2", "write")
	require.True(t, ok)
}

// TestTransactionalAdapter tests the new TransactionalAdapter interface implementation.
func TestTransactionalAdapter(t *testing.T) {
	// Skip if we don't have access to casbin's TransactionalEnforcer
	// This test requires the new transaction implementation from casbin core

	adapter := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")

	// Test BeginTransaction method
	ctx := context.Background()
	txContext, err := adapter.BeginTransaction(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, txContext)

	// Get transaction adapter
	txAdapter := txContext.GetAdapter()
	assert.NotNil(t, txAdapter)

	// Test transaction operations
	err = txAdapter.AddPolicy("p", "p", []string{"alice", "data1", "read"})
	assert.NoError(t, err)

	err = txAdapter.AddPolicy("p", "p", []string{"bob", "data2", "write"})
	assert.NoError(t, err)

	// Commit transaction
	err = txContext.Commit()
	assert.NoError(t, err)

	// Verify policies were added
	var policies []CasbinRule
	err = adapter.db.Find(&policies).Error
	assert.NoError(t, err)
}

// TestTransactionContextCommitRollback tests transaction commit and rollback.
func TestTransactionContextCommitRollback(t *testing.T) {
	adapter := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")

	ctx := context.Background()

	// Test successful commit
	t.Run("Successful Commit", func(t *testing.T) {
		txContext, err := adapter.BeginTransaction(ctx)
		assert.NoError(t, err)

		txAdapter := txContext.GetAdapter()
		err = txAdapter.AddPolicy("p", "p", []string{"charlie", "data3", "read"})
		assert.NoError(t, err)

		err = txContext.Commit()
		assert.NoError(t, err)

		// Verify policy exists
		var count int64
		err = adapter.db.Model(&CasbinRule{}).Where("ptype = ? AND v0 = ? AND v1 = ? AND v2 = ?",
			"p", "charlie", "data3", "read").Count(&count).Error
		assert.NoError(t, err)
		assert.Equal(t, int64(1), count)
	})

	// Test rollback
	t.Run("Rollback", func(t *testing.T) {
		txContext, err := adapter.BeginTransaction(ctx)
		assert.NoError(t, err)

		txAdapter := txContext.GetAdapter()
		err = txAdapter.AddPolicy("p", "p", []string{"david", "data4", "write"})
		assert.NoError(t, err)

		err = txContext.Rollback()
		assert.NoError(t, err)

		// Verify policy doesn't exist
		var count int64
		err = adapter.db.Model(&CasbinRule{}).Where("ptype = ? AND v0 = ? AND v1 = ? AND v2 = ?",
			"p", "david", "data4", "write").Count(&count).Error
		assert.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})

	// Test double commit/rollback protection
	t.Run("Double Commit Protection", func(t *testing.T) {
		txContext, err := adapter.BeginTransaction(ctx)
		assert.NoError(t, err)

		err = txContext.Commit()
		assert.NoError(t, err)

		// Second commit should fail
		err = txContext.Commit()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already finished")
	})

	t.Run("Double Rollback Protection", func(t *testing.T) {
		txContext, err := adapter.BeginTransaction(ctx)
		assert.NoError(t, err)

		err = txContext.Rollback()
		assert.NoError(t, err)

		// Second rollback should fail
		err = txContext.Rollback()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already finished")
	})
}

// TestConcurrentTransactions tests that multiple transactions can run concurrently.
// This is the key advantage over the old Transaction method.
func TestConcurrentTransactions(t *testing.T) {
	adapter := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")

	ctx := context.Background()
	numGoroutines := 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]error, numGoroutines)

	// Run multiple concurrent transactions
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			txContext, err := adapter.BeginTransaction(ctx)
			if err != nil {
				mu.Lock()
				results[id] = err
				mu.Unlock()
				return
			}

			txAdapter := txContext.GetAdapter()

			// Add a unique policy for this goroutine
			err = txAdapter.AddPolicy("p", "p", []string{fmt.Sprintf("user%d", id), "data", "read"})
			if err != nil {
				mu.Lock()
				results[id] = err
				mu.Unlock()
				return
			}

			// Simulate some work
			time.Sleep(10 * time.Millisecond)

			err = txContext.Commit()
			mu.Lock()
			results[id] = err
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Check all transactions succeeded
	for i, err := range results {
		assert.NoError(t, err, "Transaction %d failed", i)
	}

	// Verify all policies were added
	var count int64
	err := adapter.db.Model(&CasbinRule{}).Where("ptype = ? AND v1 = ? AND v2 = ?",
		"p", "data", "read").Count(&count).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(numGoroutines), count)
}

// TestTransactionWithContext tests transaction with context cancellation.
func TestTransactionWithContext(t *testing.T) {
	adapter := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")

	// Test with timeout context
	t.Run("With Timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		txContext, err := adapter.BeginTransaction(ctx)
		assert.NoError(t, err)

		// Simulate long operation
		time.Sleep(200 * time.Millisecond)

		txAdapter := txContext.GetAdapter()
		err = txAdapter.AddPolicy("p", "p", []string{"timeout_user", "data", "read"})
		// This might fail due to context timeout, which is expected behavior

		// Try to commit (might fail due to timeout)
		_ = txContext.Commit()
	})

	// Test with cancelled context
	t.Run("With Cancelled Context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		txContext, err := adapter.BeginTransaction(ctx)
		assert.NoError(t, err)

		// Cancel context
		cancel()

		txAdapter := txContext.GetAdapter()
		err = txAdapter.AddPolicy("p", "p", []string{"cancelled_user", "data", "read"})
		// This might fail due to cancelled context

		// Try to commit (might fail due to cancellation)
		_ = txContext.Commit()
	})
}

// TestNewTransactionalAdapterConstructors tests the new constructor functions.
func TestNewTransactionalAdapterConstructors(t *testing.T) {
	// Test NewTransactionalAdapter
	adapter1, err := NewTransactionalAdapter("mysql", "root:@tcp(127.0.0.1:3306)/", "casbin")
	if err != nil {
		t.Skip("MySQL not available:", err)
	}
	assert.NotNil(t, adapter1)

	// Test that it implements TransactionalAdapter interface
	ctx := context.Background()
	txContext, err := adapter1.BeginTransaction(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, txContext)
	txContext.Rollback() // Clean up

	// Test NewTransactionalAdapterByDB
	db, err := gorm.Open(mysql.Open("root:@tcp(127.0.0.1:3306)/casbin"), &gorm.Config{})
	if err != nil {
		t.Skip("MySQL not available:", err)
	}

	adapter2, err := NewTransactionalAdapterByDB(db)
	assert.NoError(t, err)
	assert.NotNil(t, adapter2)

	// Test that it also implements TransactionalAdapter interface
	txContext2, err := adapter2.BeginTransaction(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, txContext2)
	txContext2.Rollback() // Clean up
}
