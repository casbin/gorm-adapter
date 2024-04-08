Gorm Adapter
====

> In v3.0.3, method `NewAdapterByDB` creates table named `casbin_rules`,  
> we fix it to `casbin_rule` after that.  
> If you used v3.0.3 and less, and you want to update it,  
> you might need to *migrate* data manually.
> Find out more at: https://github.com/casbin/gorm-adapter/issues/78

[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/gorm-adapter)](https://goreportcard.com/report/github.com/casbin/gorm-adapter)
[![Go](https://github.com/casbin/gorm-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin/gorm-adapter/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/casbin/gorm-adapter/badge.svg?branch=master)](https://coveralls.io/github/casbin/gorm-adapter?branch=master)
[![Godoc](https://godoc.org/github.com/casbin/gorm-adapter?status.svg)](https://godoc.org/github.com/casbin/gorm-adapter)
[![Release](https://img.shields.io/github/release/casbin/gorm-adapter.svg)](https://github.com/casbin/gorm-adapter/releases/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)
[![Sourcegraph](https://sourcegraph.com/github.com/casbin/gorm-adapter/-/badge.svg)](https://sourcegraph.com/github.com/casbin/gorm-adapter?badge)

Gorm Adapter is the [Gorm](https://gorm.io/gorm) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from Gorm supported database or save policy to it.

Based on [Officially Supported Databases](https://v1.gorm.io/docs/connecting_to_the_database.html#Supported-Databases), The current supported databases are:

- MySQL
- PostgreSQL
- SQL Server
- Sqlite3
> gorm-adapter use ``github.com/glebarez/sqlite`` instead of gorm official sqlite driver ``gorm.io/driver/sqlite`` because the latter needs ``cgo`` support. But there is almost no difference between the two driver. If there is a difference in use, please submit an issue.

- other 3rd-party supported DBs in Gorm website or other places.

## Installation

    go get github.com/casbin/gorm-adapter/v3

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Initialize a Gorm adapter and use it in a Casbin enforcer:
	// The adapter will use the MySQL database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	// You can also use an already existing gorm instance with gormadapter.NewAdapterByDB(gormInstance)
	a, _ := gormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/") // Your driver and data source.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	
	// Or you can use an existing DB "abc" like this:
	// The adapter will use the table named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	// a := gormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/abc", true)

	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```
## Turn off AutoMigrate
New an adapter will use ``AutoMigrate`` by default for create table, if you want to turn it off, please use API ``TurnOffAutoMigrate(db *gorm.DB) *gorm.DB``. See example: 
```go
db, err := gorm.Open(mysql.Open("root:@tcp(127.0.0.1:3306)/casbin"), &gorm.Config{})
TurnOffAutoMigrate(db)
// a,_ := NewAdapterByDB(...)
// a,_ := NewAdapterByDBUseTableName(...)
a,_ := NewAdapterByDBWithCustomTable(...)
```
Find out more details at [gorm-adapter#162](https://github.com/casbin/gorm-adapter/issues/162)
## Customize table columns example
You can change the gorm struct tags, but the table structure must stay the same.
```go
package main

import (
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

func main() {
	// Increase the column size to 512.
	type CasbinRule struct {
		ID    uint   `gorm:"primaryKey;autoIncrement"`
		Ptype string `gorm:"size:512;uniqueIndex:unique_index"`
		V0    string `gorm:"size:512;uniqueIndex:unique_index"`
		V1    string `gorm:"size:512;uniqueIndex:unique_index"`
		V2    string `gorm:"size:512;uniqueIndex:unique_index"`
		V3    string `gorm:"size:512;uniqueIndex:unique_index"`
		V4    string `gorm:"size:512;uniqueIndex:unique_index"`
		V5    string `gorm:"size:512;uniqueIndex:unique_index"`
	}

	db, _ := gorm.Open(...)

	// Initialize a Gorm adapter and use it in a Casbin enforcer:
	// The adapter will use an existing gorm.DB instnace.
	a, _ := gormadapter.NewAdapterByDBWithCustomTable(db, &CasbinRule{}) 
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	
	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```
## Transaction
You can modify policies within a transaction.See example:
```go
package main

func main() {
	a, err := NewAdapterByDB(db)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	err = e.GetAdapter().(*Adapter).Transaction(e, func(e casbin.IEnforcer) error {
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
	if err != nil {
		// handle if transaction failed
		return
	}
}
```
## ConditionsToGormQuery

`ConditionsToGormQuery()` is a function that converts multiple query conditions into a GORM query statement
You can use the `GetAllowedObjectConditions()` API of Casbin to get conditions,
and choose the way of combining conditions through `combineType`.

`ConditionsToGormQuery()` allows Casbin to be combined with SQL, and you can use it to implement many functions.
### Example: GetAllowedRecordsForUser
* model example: [object_conditions_model.conf](examples/object_conditions_model.conf)
* policy example: [object_conditions_policy.csv](examples/object_conditions_policy.csv)

DataBase example:

|id|title|author|publisher|publish_data|price|category_id|
|--|--|--|--|--|--|--|
|1|book1|author1|publisher1|2023-04-09 16:23:42|10|1|
|2|book2|author1|publisher1|2023-04-09 16:23:44|20|2|
|3|book3|author2|publisher1|2023-04-09 16:23:44|30|1|
|4|book4|author2|publisher2|2023-04-09 16:23:45|10|3|
|5|book5|author3|publisher2|2023-04-09 16:23:45|50|1|
|6|book6|author3|publisher2|2023-04-09 16:23:46|60|2|


```go
type Book struct {
    ID          int
    Title       string
    Author      string
    Publisher   string
    PublishDate time.Time
    Price       float64
    CategoryID  int
}

func TestGetAllowedRecordsForUser(t *testing.T) {
	e, _ := casbin.NewEnforcer("examples/object_conditions_model.conf", "examples/object_conditions_policy.csv")

	conditions, err := e.GetAllowedObjectConditions("alice", "read", "r.obj.")
	if err != nil {
		panic(err)
	}
	fmt.Println(conditions)

	dsn := "root:root@tcp(127.0.0.1:3307)/test?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	fmt.Println("CombineTypeOr")
	rows, err := ConditionsToGormQuery(db, conditions, CombineTypeOr).Model(&Book{}).Rows()
	defer rows.Close()
	var b Book
	for rows.Next() {
		err := db.ScanRows(rows, &b)
		if err != nil {
			panic(err)
		}
		log.Println(b)
	}

	fmt.Println("CombineTypeAnd")
	rows, err = ConditionsToGormQuery(db, conditions, CombineTypeAnd).Model(&Book{}).Rows()
	defer rows.Close()
	for rows.Next() {
		err := db.ScanRows(rows, &b)
		if err != nil {
			panic(err)
		}
		log.Println(b)
	}
}
```

## Context Adapter

`gormadapter` supports adapter with context, the following is a timeout control implemented using context

```go
a, _ := gormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/") // Your driver and data source.
// Limited time 300s
ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
defer cancel()
err := a.AddPolicyCtx(ctx, "p", "p", []string{"alice", "data1", "read"})
if err != nil {
    panic(err)
}
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
