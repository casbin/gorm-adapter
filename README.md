Gorm Adapter
====

> In v3.0.3, method `NewAdapterByDB` creates table named `casbin_rules`,  
> we fix it to `casbin_rule` after that.  
> If you used v3.0.3 and less, and you want to update it,  
> you might need to *migrate* data manually.
> Find out more at: https://github.com/casbin/gorm-adapter/issues/78

[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/gorm-adapter)](https://goreportcard.com/report/github.com/casbin/gorm-adapter)
[![Build Status](https://travis-ci.com/casbin/gorm-adapter.svg?branch=master)](https://travis-ci.com/casbin/gorm-adapter)
[![Coverage Status](https://coveralls.io/repos/github/casbin/gorm-adapter/badge.svg?branch=master)](https://coveralls.io/github/casbin/gorm-adapter?branch=master)
[![Godoc](https://godoc.org/github.com/casbin/gorm-adapter?status.svg)](https://godoc.org/github.com/casbin/gorm-adapter)
[![Release](https://img.shields.io/github/release/casbin/gorm-adapter.svg)](https://github.com/casbin/gorm-adapter/releases/latest)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/casbin/lobby)
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

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
