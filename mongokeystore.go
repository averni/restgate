package restgate

import (
	"errors"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type MongoKeyStore struct {
	Session     *mgo.Session
	database    string
	collection  string
	keyField    string
	secretField string
}

func NewMongoKeyStore(session *mgo.Session, database string, collection string, keyField string, secretField string) (*MongoKeyStore, error) {
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
