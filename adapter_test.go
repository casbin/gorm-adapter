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
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/glebarez/sqlite"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()
	log.Print("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func testGetPolicyWithoutOrder(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()
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

func TestTransaction(t *testing.T) {
	a := initAdapter(t, "mysql", "root:@tcp(127.0.0.1:3306)/", "casbin", "casbin_rule")
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	err := e.GetAdapter().(*Adapter).Transaction(e, func(e casbin.IEnforcer) error {
		_, err := e.AddPolicy("jack", "data1", "write")
		if err != nil {
			return err
		}
		_, err = e.AddPolicy("jack", "data2", "write")
		//err = errors.New("some error")
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return
	}
}
