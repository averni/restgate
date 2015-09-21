package restgate

/*
|--------------------------------------------------------------------------
| WARNING
|--------------------------------------------------------------------------
| Never Set HTTPSProtectionOff=true In Production.
| The Key and Password will be exposed and highly unsecure otherwise!
| The database server should also use HTTPS Connection and be hidden away
|
*/

/*
Thanks to Ido Ben-Natan ("IdoBn") for postgres fix.
Thanks to Jeremy Saenz & Brendon Murphy for timing-attack protection
*/

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	e "github.com/pjebs/jsonerror"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/unrolled/render.v1"
	"log"
	"net/http"
	"strings"
)

type KeyStore interface {
	AddKey(key string, secret string) error
	MatchKey(key string, secret string) (result bool, err error)
}

type keyStoreEntry struct {
	index  int
	secret string
}

type StaticKeyStore struct {
	keyStore map[string]keyStoreEntry
	keys     []string
}

func NewStaticKeyStore(storeSize int) *StaticKeyStore {
	return &StaticKeyStore{keyStore: make(map[string]keyStoreEntry), keys: make([]string, 0, storeSize)}
}

func NewStaticKeyStoreFromKeys(keyMap map[string]string) (*StaticKeyStore, error) {
	if keyMap == nil || len(keyMap) == 0 {
		return nil, errors.New("Invalid key set")
	}
	ks := NewStaticKeyStore(len(keyMap))
	for key, secret := range keyMap {
		ks.AddKey(key, secret)
	}
	return ks, nil
}

func (ks *StaticKeyStore) AddKey(key string, secret string) error {
	if ks.keyStore == nil || ks.keys == nil {
		return errors.New("StaticKeyStore not initialized")
	}
	if key == "" || len(key) == 0 {
		return errors.New("Cannot add empty key")
	}
	ks.keys = append(ks.keys, key)
	ks.keyStore[key] = keyStoreEntry{index: len(ks.keyStore), secret: secret}
	return nil
}

func (ks *StaticKeyStore) MatchKey(key string, secret string) (authenticationPassed bool, err error) {
	authenticationPassed = false
	err = nil
	if keyEntry, ok := ks.keyStore[key]; ok {
		if secureCompare(key, ks.keys[keyEntry.index]) { //Key matches
			if (keyEntry.secret == "" && secret == "") || secureCompare(secret, keyEntry.secret) {
				authenticationPassed = true
			}
		}
	}
	return authenticationPassed, err
}

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

type MongoKeyStore struct {
	Session     *mgo.Session
	database    string
	collection  string
	keyField    string
	secretField string
}

func NewMongoKeystore(session *mgo.Session, database string, collection string, keyField string, secretField string) (*MongoKeyStore, error) {
	if database == "" {
		return nil, errors.New("Database name cannot be empty")
	}
	if collection == "" {
		return nil, errors.New("Collection name cannot be empty")
	}
	if keyField == "" {
		return nil, errors.New("Key field name cannot be empty")
	}
	return &MongoKeyStore{Session: session, database: database, collection: collection, keyField: keyField, secretField: secretField}, nil
}

func (ks *MongoKeyStore) AddKey(key string, secret string) error {
	session := ks.Session.Clone()
	defer session.Close()
	db := session.DB(ks.database)
	collection := db.C(ks.collection)
	err := collection.Insert(bson.M{ks.keyField: key, ks.secretField: secret})
	return err
}

func (ks *MongoKeyStore) MatchKey(key string, secret string) (result bool, err error) {
	session := ks.Session.Clone()
	defer session.Close()
	db := session.DB(ks.database)
	collection := db.C(ks.collection)
	criteria := bson.M{
		ks.keyField: key,
	}
	if secret != "" {
		criteria[ks.secretField] = secret
	}
	count, err := collection.Find(criteria).Count()
	if err != nil {
		return false, err
	}
	return count == 1, nil
}

type Config struct {
	ErrorMessages      map[int]map[string]string
	Context            func(r *http.Request, authenticatedKey string)
	Debug              bool
	HTTPSProtectionOff bool //Default is HTTPS Protection On
}

type RESTGate struct {
	headerKeyLabel    string
	headerSecretLabel string
	config            Config
	store             KeyStore
}

func New(headerKeyLabel string, headerSecretLabel string, store KeyStore, config Config) *RESTGate {
	t := &RESTGate{headerKeyLabel: headerKeyLabel, headerSecretLabel: headerSecretLabel, config: config, store: store}
	log.Printf("RestGate initializing")

	if headerKeyLabel == "" { //headerKeyLabel must be defined
		if t.config.Debug == true {
			log.Printf("RestGate: headerKeyLabel is not defined.")
		}
		return nil
	}

	//Default Error Messages
	if t.config.ErrorMessages == nil {
		t.config.ErrorMessages = map[int]map[string]string{
			1:  e.New(1, "No Key Or Secret", "", "com.github.pjebs.restgate").Render(),
			2:  e.New(2, "Unauthorized Access", "", "com.github.pjebs.restgate").Render(),
			3:  e.New(3, "Please use HTTPS connection", "", "com.github.pjebs.restgate").Render(),
			99: e.New(99, "Software Developers have not setup authentication correctly", "", "com.github.pjebs.restgate").Render(),
		}
	} else {
		if _, ok := t.config.ErrorMessages[1]; !ok {
			t.config.ErrorMessages[1] = e.New(1, "No Key Or Secret", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[2]; !ok {
			t.config.ErrorMessages[2] = e.New(2, "Unauthorized Access", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[3]; !ok {
			t.config.ErrorMessages[3] = e.New(3, "Please use HTTPS connection", "", "com.github.pjebs.restgate").Render()
		}

		if _, ok := t.config.ErrorMessages[99]; !ok {
			t.config.ErrorMessages[99] = e.New(99, "Software Developers have not setup authentication correctly", "", "com.github.pjebs.restgate").Render()
		}
	}

	//Check if HTTPS Protection has been turned off
	if t.config.HTTPSProtectionOff {
		//HTTPS Protection is off
		log.Printf("\x1b[31mWARNING: HTTPS Protection is off. This is potentially insecure!\x1b[39;49m")
	}

	return t
}

func (self *RESTGate) ServeHTTP(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {

	//Check if HTTPS Protection has been turned off
	if !self.config.HTTPSProtectionOff {
		//HTTPS Protection is on so we must check it
		if !(strings.EqualFold(req.URL.Scheme, "https") || req.TLS != nil) {
			r := render.New(render.Options{})
			r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[3]) //"Please use HTTPS connection"
			return
		}
	}

	//Check key in Header
	key := req.Header.Get(self.headerKeyLabel)
	secret := req.Header.Get(self.headerSecretLabel)

	if key == "" {
		//Authentication Information not included in request
		r := render.New(render.Options{})
		r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[1]) //"No Key Or Secret"
		return
	}

	authenticationPassed, err := self.store.MatchKey(key, secret)
	if err != nil {
		if self.config.Debug == true {
			log.Printf("RestGate: Run time error: %+v", err)
		}
		r := render.New(render.Options{})
		jerr := e.New(2, err.Error(), "", "com.github.pjebs.restgate").Render()
		r.JSON(w, http.StatusUnauthorized, jerr) //"Unauthorized Access"
	}
	if !authenticationPassed {
		r := render.New(render.Options{})
		r.JSON(w, http.StatusUnauthorized, self.config.ErrorMessages[2]) //"Unauthorized Access"
	} else {
		if self.config.Context != nil {
			self.config.Context(req, key)
		}
		next(w, req)
	}
}

// secureCompare performs a constant time compare of two strings to limit timing attacks.
func secureCompare(given string, actual string) bool {
	if subtle.ConstantTimeEq(int32(len(given)), int32(len(actual))) == 1 {
		return subtle.ConstantTimeCompare([]byte(given), []byte(actual)) == 1
	} else {
		/* Securely compare actual to itself to keep constant time, but always return false */
		return subtle.ConstantTimeCompare([]byte(actual), []byte(actual)) == 1 && false
	}
}
