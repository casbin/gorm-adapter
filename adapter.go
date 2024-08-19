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
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"gorm.io/plugin/dbresolver"
)

const (
	defaultDatabaseName = "casbin"
	defaultTableName    = "casbin_rule"
)

const disableMigrateKey = "disableMigrateKey"
const customTableKey = "customTableKey"

type CasbinRule struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"size:100"`
	V0    string `gorm:"size:100"`
	V1    string `gorm:"size:100"`
	V2    string `gorm:"size:100"`
	V3    string `gorm:"size:100"`
	V4    string `gorm:"size:100"`
	V5    string `gorm:"size:100"`
}

func (CasbinRule) TableName() string {
	return "casbin_rule"
}

type Filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

type BatchFilter struct {
	filters []Filter
}

// Adapter represents the Gorm adapter for policy storage.
type Adapter struct {
	driverName     string
	dataSourceName string
	databaseName   string
	tablePrefix    string
	tableName      string
	dbSpecified    bool
	db             *gorm.DB
	isFiltered     bool
	transactionMu  *sync.Mutex
	muInitialize   sync.Once
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
	sqlDB, err := a.db.DB()
	if err != nil {
		panic(err)
	}
	err = sqlDB.Close()
	if err != nil {
		panic(err)
	}
}

// Select conn according to table name（use map store name-index）
type specificPolicy int

func (p *specificPolicy) Resolve(connPools []gorm.ConnPool) gorm.ConnPool {
	return connPools[*p]
}

type DbPool struct {
	dbMap  map[string]specificPolicy
	policy *specificPolicy
	source *gorm.DB
}

func (dbPool *DbPool) switchDb(dbName string) *gorm.DB {
	*dbPool.policy = dbPool.dbMap[dbName]
	return dbPool.source.Clauses(dbresolver.Write)
}

// NewAdapter is the constructor for Adapter.
// Params : databaseName,tableName,dbSpecified
//
//	databaseName,{tableName/dbSpecified}
//	{database/dbSpecified}
//
// databaseName and tableName are user defined.
// Their default value are "casbin" and "casbin_rule"
//
// dbSpecified is an optional bool parameter. The default value is false.
// It's up to whether you have specified an existing DB in dataSourceName.
// If dbSpecified == true, you need to make sure the DB in dataSourceName exists.
// If dbSpecified == false, the adapter will automatically create a DB named databaseName.
func NewAdapter(driverName string, dataSourceName string, params ...interface{}) (*Adapter, error) {
	a := &Adapter{}
	a.driverName = driverName
	a.dataSourceName = dataSourceName

	a.tableName = defaultTableName
	a.databaseName = defaultDatabaseName
	a.dbSpecified = false
	a.transactionMu = &sync.Mutex{}

	if len(params) == 1 {
		switch p1 := params[0].(type) {
		case bool:
			a.dbSpecified = p1
		case string:
			a.databaseName = p1
		default:
			return nil, errors.New("wrong format")
		}
	} else if len(params) == 2 {
		switch p2 := params[1].(type) {
		case bool:
			a.dbSpecified = p2
			p1, ok := params[0].(string)
			if !ok {
				return nil, errors.New("wrong format")
			}
			a.databaseName = p1
		case string:
			p1, ok := params[0].(string)
			if !ok {
				return nil, errors.New("wrong format")
			}
			a.databaseName = p1
			a.tableName = p2
		default:
			return nil, errors.New("wrong format")
		}
	} else if len(params) == 3 {
		if p3, ok := params[2].(bool); ok {
			a.dbSpecified = p3
			a.databaseName = params[0].(string)
			a.tableName = params[1].(string)
		} else {
			return nil, errors.New("wrong format")
		}
	} else if len(params) != 0 {
		return nil, errors.New("too many parameters")
	}

	// Open the DB, create it if not existed.
	err := a.Open()
	if err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

// NewAdapterByDBUseTableName creates gorm-adapter by an existing Gorm instance and the specified table prefix and table name
// Example: gormadapter.NewAdapterByDBUseTableName(&db, "cms", "casbin") Automatically generate table name like this "cms_casbin"
func NewAdapterByDBUseTableName(db *gorm.DB, prefix string, tableName string) (*Adapter, error) {
	if len(tableName) == 0 {
		tableName = defaultTableName
	}

	a := &Adapter{
		tablePrefix:   prefix,
		tableName:     tableName,
		transactionMu: &sync.Mutex{},
	}

	a.db = db.Scopes(a.casbinRuleTable()).Session(&gorm.Session{Context: db.Statement.Context})

	err := a.createTable()
	if err != nil {
		return nil, err
	}

	return a, nil
}

// InitDbResolver multiple databases support
// Example usage:
// dbPool,err := InitDbResolver([]gorm.Dialector{mysql.Open(dsn),mysql.Open(dsn2)},[]string{"casbin1","casbin2"})
// a := initAdapterWithGormInstanceByMulDb(t,dbPool,"casbin1","","casbin_rule1")
// a = initAdapterWithGormInstanceByMulDb(t,dbPool,"casbin2","","casbin_rule2")/*
func InitDbResolver(dbArr []gorm.Dialector, dbNames []string) (DbPool, error) {
	if len(dbArr) == 0 {
		panic("dbArr len is 0")
	}
	source, e := gorm.Open(dbArr[0])
	if e != nil {
		panic(e.Error())
	}
	var p specificPolicy
	p = 0
	err := source.Use(dbresolver.Register(dbresolver.Config{Policy: &p, Sources: dbArr}))
	dbMap := make(map[string]specificPolicy)
	for i := 0; i < len(dbNames); i++ {
		dbMap[dbNames[i]] = specificPolicy(i)
	}
	return DbPool{dbMap: dbMap, policy: &p, source: source}, err
}

func NewAdapterByMulDb(dbPool DbPool, dbName string, prefix string, tableName string) (*Adapter, error) {
	//change DB
	db := dbPool.switchDb(dbName)

	return NewAdapterByDBUseTableName(db, prefix, tableName)
}

// NewFilteredAdapter is the constructor for FilteredAdapter.
// Casbin will not automatically call LoadPolicy() for a filtered adapter.
func NewFilteredAdapter(driverName string, dataSourceName string, params ...interface{}) (*Adapter, error) {
	adapter, err := NewAdapter(driverName, dataSourceName, params...)
	if err != nil {
		return nil, err
	}
	adapter.isFiltered = true
	return adapter, err
}

// NewFilteredAdapterByDB is the constructor for FilteredAdapter.
// Casbin will not automatically call LoadPolicy() for a filtered adapter.
func NewFilteredAdapterByDB(db *gorm.DB, prefix string, tableName string) (*Adapter, error) {
	adapter := &Adapter{
		tablePrefix:   prefix,
		tableName:     tableName,
		isFiltered:    true,
		transactionMu: &sync.Mutex{},
	}
	adapter.db = db.Scopes(adapter.casbinRuleTable()).Session(&gorm.Session{Context: db.Statement.Context})

	return adapter, nil
}

// NewAdapterByDB creates gorm-adapter by an existing Gorm instance
func NewAdapterByDB(db *gorm.DB) (*Adapter, error) {
	return NewAdapterByDBUseTableName(db, "", defaultTableName)
}

func TurnOffAutoMigrate(db *gorm.DB) {
	ctx := db.Statement.Context
	if ctx == nil {
		ctx = context.Background()
	}

	ctx = context.WithValue(ctx, disableMigrateKey, false)

	*db = *db.WithContext(ctx)
}

func NewAdapterByDBWithCustomTable(db *gorm.DB, t interface{}, tableName ...string) (*Adapter, error) {
	ctx := db.Statement.Context
	if ctx == nil {
		ctx = context.Background()
	}

	ctx = context.WithValue(ctx, customTableKey, t)

	curTableName := defaultTableName
	if len(tableName) > 0 {
		curTableName = tableName[0]
	}

	return NewAdapterByDBUseTableName(db.WithContext(ctx), "", curTableName)
}

func openDBConnection(driverName, dataSourceName string) (*gorm.DB, error) {
	var err error
	var db *gorm.DB
	if driverName == "postgres" {
		db, err = gorm.Open(postgres.Open(dataSourceName), &gorm.Config{})
	} else if driverName == "mysql" {
		db, err = gorm.Open(mysql.Open(dataSourceName), &gorm.Config{})
	} else if driverName == "sqlserver" {
		db, err = gorm.Open(sqlserver.Open(dataSourceName), &gorm.Config{})
	} else if driverName == "sqlite3" {
		db, err = gorm.Open(sqlite.Open(dataSourceName), &gorm.Config{})
	} else {
		return nil, errors.New("Database dialect '" + driverName + "' is not supported. Supported databases are postgres, mysql, sqlserver and sqlite3")
	}
	if err != nil {
		return nil, err
	}
	return db, err
}

func (a *Adapter) createDatabase() error {
	var err error
	db, err := openDBConnection(a.driverName, a.dataSourceName)
	if err != nil {
		return err
	}
	if a.driverName == "postgres" {
		if err = db.Exec("CREATE DATABASE " + a.databaseName).Error; err != nil {
			// 42P04 is	duplicate_database
			if strings.Contains(fmt.Sprintf("%s", err), "42P04") {
				return nil
			}
		}
	} else if a.driverName != "sqlite3" && a.driverName != "sqlserver" {
		err = db.Exec("CREATE DATABASE IF NOT EXISTS " + a.databaseName).Error
	}
	if err != nil {
		return err
	}
	return nil
}

func (a *Adapter) Open() error {
	var err error
	var db *gorm.DB

	if a.dbSpecified {
		db, err = openDBConnection(a.driverName, a.dataSourceName)
		if err != nil {
			return err
		}
	} else {
		if err = a.createDatabase(); err != nil {
			return err
		}
		if a.driverName == "postgres" {
			db, err = openDBConnection(a.driverName, a.dataSourceName+" dbname="+a.databaseName)
		} else if a.driverName == "sqlite3" {
			db, err = openDBConnection(a.driverName, a.dataSourceName)
		} else if a.driverName == "sqlserver" {
			db, err = openDBConnection(a.driverName, a.dataSourceName+"?database="+a.databaseName)
		} else {
			db, err = openDBConnection(a.driverName, a.dataSourceName+a.databaseName)
		}
		if err != nil {
			return err
		}
	}

	a.db = db.Scopes(a.casbinRuleTable()).Session(&gorm.Session{})
	return a.createTable()
}

// AddLogger adds logger to db
func (a *Adapter) AddLogger(l logger.Interface) {
	a.db = a.db.Session(&gorm.Session{Logger: l, Context: a.db.Statement.Context})
}

func (a *Adapter) Close() error {
	finalizer(a)
	return nil
}

// getTableInstance return the dynamic table name
func (a *Adapter) getTableInstance() *CasbinRule {
	return &CasbinRule{}
}

func (a *Adapter) getFullTableName() string {
	if a.tablePrefix != "" {
		if strings.HasSuffix(a.tablePrefix, "_") {
			return a.tablePrefix + a.tableName
		}
		return a.tablePrefix + "_" + a.tableName
	}
	return a.tableName
}

func (a *Adapter) casbinRuleTable() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		tableName := a.getFullTableName()
		return db.Table(tableName)
	}
}

func (a *Adapter) createTable() error {
	disableMigrate := a.db.Statement.Context.Value(disableMigrateKey)
	if disableMigrate != nil {
		return nil
	}

	t := a.db.Statement.Context.Value(customTableKey)

	if t != nil {
		return a.db.AutoMigrate(t)
	}

	t = a.getTableInstance()
	if err := a.db.AutoMigrate(t); err != nil {
		return err
	}

	tableName := a.getFullTableName()
	index := strings.ReplaceAll("idx_"+tableName, ".", "_")
	hasIndex := a.db.Migrator().HasIndex(t, index)
	if !hasIndex {
		if err := a.db.Exec(fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (ptype,v0,v1,v2,v3,v4,v5)", index, tableName)).Error; err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) dropTable() error {
	t := a.db.Statement.Context.Value(customTableKey)
	if t == nil {
		return a.db.Migrator().DropTable(a.getTableInstance())
	}

	return a.db.Migrator().DropTable(t)
}

func (a *Adapter) truncateTable() error {
	var sql string
	switch a.db.Config.Name() {
	case sqlite.DriverName:
		sql = fmt.Sprintf("delete from %s", a.getFullTableName())
	case "sqlite3":
		sql = fmt.Sprintf("delete from %s", a.getFullTableName())
	case "postgres":
		sql = fmt.Sprintf("truncate table %s RESTART IDENTITY", a.getFullTableName())
	case "sqlserver":
		sql = fmt.Sprintf("truncate table %s", a.getFullTableName())
	case "mysql":
		sql = fmt.Sprintf("truncate table %s", a.getFullTableName())
	default:
		sql = fmt.Sprintf("truncate table %s", a.getFullTableName())
	}
	return a.db.Exec(sql).Error
}

func loadPolicyLine(line CasbinRule, model model.Model) error {
	var p = []string{line.Ptype,
		line.V0, line.V1, line.V2,
		line.V3, line.V4, line.V5}

	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	index += 1
	p = p[:index]
	err := persist.LoadPolicyArray(p, model)
	if err != nil {
		return err
	}
	return nil
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	return a.LoadPolicyCtx(context.Background(), model)
}

// LoadPolicyCtx loads policy from database.
func (a *Adapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	var lines []CasbinRule
	if err := a.db.WithContext(ctx).Order("ID").Find(&lines).Error; err != nil {
		return err
	}
	err := a.Preview(&lines, model)
	if err != nil {
		return err
	}
	for _, line := range lines {
		err := loadPolicyLine(line, model)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	var lines []CasbinRule

	batchFilter := BatchFilter{
		filters: []Filter{},
	}
	switch filterValue := filter.(type) {
	case Filter:
		batchFilter.filters = []Filter{filterValue}
	case *Filter:
		batchFilter.filters = []Filter{*filterValue}
	case []Filter:
		batchFilter.filters = filterValue
	case BatchFilter:
		batchFilter = filterValue
	case *BatchFilter:
		batchFilter = *filterValue
	default:
		return errors.New("unsupported filter type")
	}

	for _, f := range batchFilter.filters {
		if err := a.db.Scopes(a.filterQuery(a.db, f)).Order("ID").Find(&lines).Error; err != nil {
			return err
		}

		for _, line := range lines {
			err := loadPolicyLine(line, model)
			if err != nil {
				return err
			}
		}
	}
	a.isFiltered = true

	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

// filterQuery builds the gorm query to match the rule filter to use within a scope.
func (a *Adapter) filterQuery(db *gorm.DB, filter Filter) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if len(filter.Ptype) > 0 {
			db = db.Where("ptype in (?)", filter.Ptype)
		}
		if len(filter.V0) > 0 {
			db = db.Where("v0 in (?)", filter.V0)
		}
		if len(filter.V1) > 0 {
			db = db.Where("v1 in (?)", filter.V1)
		}
		if len(filter.V2) > 0 {
			db = db.Where("v2 in (?)", filter.V2)
		}
		if len(filter.V3) > 0 {
			db = db.Where("v3 in (?)", filter.V3)
		}
		if len(filter.V4) > 0 {
			db = db.Where("v4 in (?)", filter.V4)
		}
		if len(filter.V5) > 0 {
			db = db.Where("v5 in (?)", filter.V5)
		}
		return db
	}
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) CasbinRule {
	line := a.getTableInstance()

	line.Ptype = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return *line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	return a.SavePolicyCtx(context.Background(), model)
}

// SavePolicyCtx saves policy to database.
func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	var err error
	tx := a.db.WithContext(ctx).Clauses(dbresolver.Write).Begin()

	err = a.truncateTable()

	if err != nil {
		tx.Rollback()
		return err
	}

	var lines []CasbinRule
	flushEvery := 1000
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
			if len(lines) > flushEvery {
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&lines).Error; err != nil {
					tx.Rollback()
					return err
				}
				lines = nil
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
			if len(lines) > flushEvery {
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&lines).Error; err != nil {
					tx.Rollback()
					return err
				}
				lines = nil
			}
		}
	}
	if len(lines) > 0 {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&lines).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	err = tx.Commit().Error
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

// AddPolicyCtx adds a policy rule to the storage.
func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	err := a.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&line).Error
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

// RemovePolicyCtx removes a policy rule from the storage.
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	err := a.rawDelete(ctx, a.db, line) //can't use db.Delete as we're not using primary key https://gorm.io/docs/update.html
	return err
}

// AddPolicies adds multiple policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []CasbinRule
	for _, rule := range rules {
		line := a.savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}
	return a.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&lines).Error
}

// Transaction perform a set of operations within a transaction
func (a *Adapter) Transaction(e casbin.IEnforcer, fc func(casbin.IEnforcer) error, opts ...*sql.TxOptions) error {
	// ensure the transactionMu is initialized
	if a.transactionMu == nil {
		a.muInitialize.Do(func() {
			if a.transactionMu == nil {
				a.transactionMu = &sync.Mutex{}
			}
		})
	}
	// lock the transactionMu to ensure the transaction is thread-safe
	a.transactionMu.Lock()
	defer a.transactionMu.Unlock()
	var err error
	oriAdapter := a.db
	// reload policy from database to sync with the transaction
	defer func() {
		e.SetAdapter(&Adapter{db: oriAdapter, transactionMu: a.transactionMu})
		err = e.LoadPolicy()
		if err != nil {
			panic(err)
		}
	}()
	copyDB := *a.db
	tx := copyDB.Begin(opts...)
	b := &Adapter{db: tx, transactionMu: a.transactionMu}
	// copy enforcer to set the new adapter with transaction tx
	copyEnforcer := e
	copyEnforcer.SetAdapter(b)
	err = fc(copyEnforcer)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit().Error
	return err
}

// RemovePolicies removes multiple policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.RemovePoliciesCtx(context.Background(), sec, ptype, rules)
}

// RemovePoliciesCtx removes multiple policy rules from the storage.
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	return a.db.Transaction(func(tx *gorm.DB) error {
		for _, rule := range rules {
			line := a.savePolicyLine(ptype, rule)
			if err := a.rawDelete(ctx, tx, line); err != nil { //can't use db.Delete as we're not using primary key https://gorm.io/docs/update.html
			}
		}
		return nil
	})
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

// RemoveFilteredPolicyCtx removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := a.getTableInstance()

	line.Ptype = ptype

	if fieldIndex == -1 {
		return a.rawDelete(ctx, a.db, *line)
	}

	err := checkQueryField(fieldValues)
	if err != nil {
		return err
	}

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	err = a.rawDelete(ctx, a.db, *line)
	return err
}

// checkQueryfield make sure the fields won't all be empty (string --> "")
func checkQueryField(fieldValues []string) error {
	for _, fieldValue := range fieldValues {
		if fieldValue != "" {
			return nil
		}
	}
	return errors.New("the query field cannot all be empty string (\"\"), please check")
}

func (a *Adapter) rawDelete(ctx context.Context, db *gorm.DB, line CasbinRule) error {
	queryArgs := []interface{}{line.Ptype}

	queryStr := "ptype = ?"
	if line.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, line.V0)
	}
	if line.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, line.V1)
	}
	if line.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, line.V2)
	}
	if line.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, line.V3)
	}
	if line.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, line.V4)
	}
	if line.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, line.V5)
	}
	args := append([]interface{}{queryStr}, queryArgs...)
	err := db.WithContext(ctx).Delete(a.getTableInstance(), args...).Error
	return err
}

func appendWhere(line CasbinRule) (string, []interface{}) {
	queryArgs := []interface{}{line.Ptype}

	queryStr := "ptype = ?"
	if line.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, line.V0)
	}
	if line.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, line.V1)
	}
	if line.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, line.V2)
	}
	if line.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, line.V3)
	}
	if line.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, line.V4)
	}
	if line.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, line.V5)
	}
	return queryStr, queryArgs
}

// UpdatePolicy updates a new policy rule to DB.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	oldLine := a.savePolicyLine(ptype, oldRule)
	newLine := a.savePolicyLine(ptype, newPolicy)
	return a.db.Model(&oldLine).Where(&oldLine).Updates(newLine).Error
}

func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	oldPolicies := make([]CasbinRule, 0, len(oldRules))
	newPolicies := make([]CasbinRule, 0, len(oldRules))
	for _, oldRule := range oldRules {
		oldPolicies = append(oldPolicies, a.savePolicyLine(ptype, oldRule))
	}
	for _, newRule := range newRules {
		newPolicies = append(newPolicies, a.savePolicyLine(ptype, newRule))
	}
	tx := a.db.Begin()
	for i := range oldPolicies {
		if err := tx.Model(&oldPolicies[i]).Where(&oldPolicies[i]).Updates(newPolicies[i]).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	// UpdateFilteredPolicies deletes old rules and adds new rules.
	line := a.getTableInstance()

	line.Ptype = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	newP := make([]CasbinRule, 0, len(newPolicies))
	oldP := make([]CasbinRule, 0)
	for _, newRule := range newPolicies {
		newP = append(newP, a.savePolicyLine(ptype, newRule))
	}

	tx := a.db.Begin()
	str, args := line.queryString()
	if err := tx.Where(str, args...).Find(&oldP).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Where(str, args...).Delete([]CasbinRule{}).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	for i := range newP {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&newP[i]).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldP {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, tx.Commit().Error
}

// Preview Pre-checking to avoid causing partial load success and partial failure deep
func (a *Adapter) Preview(rules *[]CasbinRule, model model.Model) error {
	j := 0
	for i, rule := range *rules {
		r := []string{rule.Ptype,
			rule.V0, rule.V1, rule.V2,
			rule.V3, rule.V4, rule.V5}
		index := len(r) - 1
		for r[index] == "" {
			index--
		}
		index += 1
		p := r[:index]
		key := p[0]
		sec := key[:1]
		ok, err := model.HasPolicyEx(sec, key, p[1:])
		if err != nil {
			return err
		}
		if ok {
			(*rules)[j], (*rules)[i] = rule, (*rules)[j]
			j++
		}
	}
	(*rules) = (*rules)[j:]
	return nil
}

func (a *Adapter) GetDb() *gorm.DB {
	return a.db
}

func (c *CasbinRule) queryString() (interface{}, []interface{}) {
	queryArgs := []interface{}{c.Ptype}

	queryStr := "ptype = ?"
	if c.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, c.V0)
	}
	if c.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, c.V1)
	}
	if c.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, c.V2)
	}
	if c.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, c.V3)
	}
	if c.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, c.V4)
	}
	if c.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, c.V5)
	}

	return queryStr, queryArgs
}

func (c *CasbinRule) toStringPolicy() []string {
	policy := make([]string, 0)
	if c.Ptype != "" {
		policy = append(policy, c.Ptype)
	}
	if c.V0 != "" {
		policy = append(policy, c.V0)
	}
	if c.V1 != "" {
		policy = append(policy, c.V1)
	}
	if c.V2 != "" {
		policy = append(policy, c.V2)
	}
	if c.V3 != "" {
		policy = append(policy, c.V3)
	}
	if c.V4 != "" {
		policy = append(policy, c.V4)
	}
	if c.V5 != "" {
		policy = append(policy, c.V5)
	}
	return policy
}

// CombineType represents different types of condition combining strategies
type CombineType uint32

const (
	CombineTypeOr  CombineType = iota // Combine conditions with OR operator
	CombineTypeAnd                    // Combine conditions with AND operator
)

// ConditionsToGormQuery is a function that converts multiple query conditions into a GORM query statement
// You can use the GetAllowedObjectConditions() API of Casbin to get conditions,
// and choose the way of combining conditions through combineType.
func ConditionsToGormQuery(db *gorm.DB, conditions []string, combineType CombineType) *gorm.DB {
	queryDB := db
	for _, cond := range conditions {
		switch combineType {
		case CombineTypeOr:
			queryDB = queryDB.Or(cond)
		case CombineTypeAnd:
			queryDB = queryDB.Where(cond)
		}
	}
	return queryDB
}
