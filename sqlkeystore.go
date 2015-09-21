package restgate

import (
	"database/sql"
	"errors"
	"fmt"
)

type SQLKeyStore struct {
	DB           *sql.DB
	database     string
	tableName    string
	keyColumn    string
	secretColumn string
	postgres     bool
}

func NewSQLKeystore(db *sql.DB, database string, tableName string, keyColumn string, secretColumn string, postgres bool) (*SQLKeyStore, error) {
	if database == "" {
		return nil, errors.New("Database name cannot be empty")
	}
	if tableName == "" {
		return nil, errors.New("Table name cannot be empty")
	}
	if keyColumn == "" {
		return nil, errors.New("Key column name cannot be empty")
	}
	return &SQLKeyStore{DB: db, database: database, tableName: tableName, keyColumn: keyColumn, secretColumn: secretColumn, postgres: postgres}, nil
}

func (ks *SQLKeyStore) AddKey(key string, secret string) error {
	secretDoesntExists := len(ks.secretColumn) == 0 || ks.secretColumn == ""
	var preparedStatement string
	if secretDoesntExists {
		preparedStatement = fmt.Sprintf("INSERT INTO `%v` (%v) VALUES (?)", ks.tableName, ks.keyColumn)
	} else {
		preparedStatement = fmt.Sprintf("INSERT INTO `%v` (%v, %v) VALUES (?, ?)", ks.tableName, ks.keyColumn, ks.secretColumn)
	}
	stmt, err := ks.DB.Prepare(preparedStatement)
	if err != nil {
		return err
	}
	defer stmt.Close()
	if secretDoesntExists {
		_, err = stmt.Exec(key)
	} else {
		_, err = stmt.Exec(key, secret)
	}
	return err
}

func (ks *SQLKeyStore) MatchKey(key string, secret string) (result bool, err error) {
	secretDoesntExists := len(ks.secretColumn) == 0 || ks.secretColumn == ""
	var preparedStatement string
	if secretDoesntExists {
		if ks.postgres == false { //COUNT(*) is definately faster on MYISAM and possibly InnoDB (MySQL engines)
			preparedStatement = fmt.Sprintf("SELECT COUNT(1) FROM `%v` WHERE `%v`=?", ks.tableName, ks.keyColumn)
		} else {
			preparedStatement = fmt.Sprintf("SELECT COUNT(%v) FROM %v WHERE %v=$1", key, ks.tableName, ks.keyColumn)
		}
	} else {
		if ks.postgres == false {
			preparedStatement = fmt.Sprintf("SELECT COUNT(*) FROM `%v` WHERE `%v`=? AND `%v`=?", ks.tableName, ks.keyColumn, ks.secretColumn)
		} else {
			preparedStatement = fmt.Sprintf("SELECT COUNT(%v) FROM %v WHERE %v=$1 AND %v=$2", key, ks.tableName, ks.keyColumn, ks.secretColumn)
		}
	}
	stmt, err := ks.DB.Prepare(preparedStatement)
	if err != nil {
		return false, err
	}
	defer stmt.Close()
	var count int //stores query result
	if secretDoesntExists {
		err = stmt.QueryRow(key).Scan(&count)
	} else {
		err = stmt.QueryRow(key, secret).Scan(&count)
	}

	// log.Printf("result error: %+v", err)
	// log.Printf("count: %+v", count)

	if err == nil && count == 1 { // key found
		return true, nil
	}
	return false, nil
}
