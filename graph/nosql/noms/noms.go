package noms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	// "github.com/globalsign/mgo"
	// "github.com/globalsign/mgo/bson"

	"github.com/attic-labs/noms/go/datas"
	"github.com/attic-labs/noms/go/marshal"
	"github.com/attic-labs/noms/go/spec"
	"github.com/attic-labs/noms/go/types"

	"github.com/cayleygraph/cayley/graph"
	"github.com/cayleygraph/cayley/graph/nosql"

	"github.com/mitchellh/mapstructure"
)

const Type = "noms"
const prefix = "master"

// var (
// 	_ nosql.BatchInserter = (*DB)(nil)
// )

type DB struct {
	db    datas.Database
	colls map[string]string
}

type Query struct {
	// c     *collection
	// limit int
	// query bson.M
}

// noms type
type nQuad struct {
	Subject   string
	Predicate string
	Object    string
	Label     string
	Added     int
}

type nNode struct {
	Type  string
	Value interface{}
	Refs  int
}

func init() {
	fmt.Println("noms:init()")
	nosql.Register(Type, nosql.Registration{
		NewFunc:      Open,
		InitFunc:     Create,
		IsPersistent: true,
	})
}

func dialDB(addr string, opt graph.Options) (*DB, error) {
	fmt.Println("noms:dialDB()")

	databaseLocation := "./data"
	s, err := spec.ForDatabase(databaseLocation)

	if err != nil {
		panic("Failed process the spec of the database")
	}

	// ds := db.GetDataset(fmt.Sprintf("%s-relationship", branchName))

	// sess, err := dialMongo(addr, opt)
	// if err != nil {
	// 	return nil, err
	// }
	// dbName, err := opt.StringKey("database_name", nosql.DefaultDBName)
	// if err != nil {
	// 	return nil, err
	// }
	return &DB{
		db:    s.GetDatabase(),
		colls: make(map[string]string),
	}, nil
}

func Create(addr string, opt graph.Options) (nosql.Database, error) {
	return dialDB(addr, opt)
}

func Open(addr string, opt graph.Options) (nosql.Database, error) {
	return dialDB(addr, opt)
}

func getItems(ds datas.Dataset) types.Map {
	hv, ok := ds.MaybeHeadValue()
	if ok {
		return hv.(types.Map)
	}
	return types.NewMap(ds.Database())
}

func getItemByKey(ds datas.Dataset, key string) (types.Value, error) {

	d := getItems(ds)
	item, ok := d.MaybeGet(types.String(key))

	if !ok {
		return nil, errors.New("No item found")
	}

	return item, nil
}

// type collection struct {
// 	c         *mgo.Collection
// 	compPK    bool // compose PK from existing keys; if false, use _id instead of target field
// 	primary   nosql.Index
// 	secondary []nosql.Index
// }

func (db *DB) Close() error {
	// db.sess.Close()
	return nil
}

func (db *DB) EnsureIndex(ctx context.Context, col string, primary nosql.Index, secondary []nosql.Index) error {
	fmt.Printf("noms:EnsureIndex() - %s \n", col)

	if primary.Type != nosql.StringExact {
		return fmt.Errorf("unsupported type of primary index: %v", primary.Type)
	}

	colName := fmt.Sprintf("%s__%s", prefix, col)

	ds := db.db.GetDataset(colName)

	_, err := db.db.CommitValue(ds, getItems(ds))
	if err != nil {
		fmt.Errorf("Error committing: %s", err)
		return err
	}

	db.colls[col] = colName

	return nil
}

func (db *DB) FindByKey(ctx context.Context, col string, key nosql.Key) (nosql.Document, error) {
	fmt.Printf("noms:FindByKey() %s / %s\n", col, compKey(key))

	item, err := getItemByKey(db.db.GetDataset(db.colls[col]), compKey(key))

	if err != nil {
		return nil, nosql.ErrNotFound
	}

	if col == "quads" {

		var nq nQuad
		err = marshal.Unmarshal(item, &nq)
		if err != nil {
			return nil, fmt.Errorf("GetNFindByKeyode, Unable to Unmarshal")
		}

		doc, _ := quadNomsToDoc(nq)
		fmt.Printf("noms:FindByKey() %v", doc)
		return doc, nil
	}

	// c := db.colls[col]
	// var m bson.M
	// err := c.c.FindId(compKey(key)).One(&m)
	// if err == mgo.ErrNotFound {
	// 	return nil, nosql.ErrNotFound
	// } else if err != nil {
	// 	return nil, err
	// }
	return nosql.Document{}, nil
}

func (db *DB) Insert(ctx context.Context, col string, key nosql.Key, d nosql.Document) (nosql.Key, error) {
	fmt.Printf("noms:Insert() col: %s | key: %s \n", col, compKey(key))

	// Ignore log insert since noms tracks all transaction
	if col == "log" {
		return nosql.Key{}, nil
	}

	return nosql.Key{}, nil
}

func (db *DB) Query(col string) nosql.Query {
	fmt.Printf("noms:Query() %s\n", col)
	return &Query{}
}
func (db *DB) Update(col string, key nosql.Key) nosql.Update {
	fmt.Printf("noms:Update() %s | %s\n", col, compKey(key))
	return &Update{col: col, db: db.db, dsName: db.colls[col], key: key}
}

func (db *DB) Delete(col string) nosql.Delete {
	fmt.Printf("noms:Delete() %s \n", col)
	return &Delete{}
}

// func toBsonValue(v nosql.Value) interface{} {
// 	fmt.Println("noms:toBsonValue()")
// 	switch v := v.(type) {
// 	case nil:
// 		return nil
// 	case nosql.Document:
// 		return toBsonDoc(v)
// 	case nosql.Strings:
// 		return []string(v)
// 	case nosql.String:
// 		return string(v)
// 	case nosql.Int:
// 		return int64(v)
// 	case nosql.Float:
// 		return float64(v)
// 	case nosql.Bool:
// 		return bool(v)
// 	case nosql.Time:
// 		return time.Time(v)
// 	case nosql.Bytes:
// 		return []byte(v)
// 	default:
// 		panic(fmt.Errorf("unsupported type: %T", v))
// 	}
// }
// func fromBsonValue(v interface{}) nosql.Value {
// 	fmt.Println("noms:fromBsonValue()")
// 	switch v := v.(type) {
// 	case nil:
// 		return nil
// 	case bson.M:
// 		return fromBsonDoc(v)
// 	case []interface{}:
// 		arr := make(nosql.Strings, 0, len(v))
// 		for _, s := range v {
// 			sv := fromBsonValue(s)
// 			str, ok := sv.(nosql.String)
// 			if !ok {
// 				panic(fmt.Errorf("unsupported value in array: %T", sv))
// 			}
// 			arr = append(arr, string(str))
// 		}
// 		return arr
// 	case bson.ObjectId:
// 		return nosql.String(objidString(v))
// 	case string:
// 		return nosql.String(v)
// 	case int:
// 		return nosql.Int(v)
// 	case int64:
// 		return nosql.Int(v)
// 	case float64:
// 		return nosql.Float(v)
// 	case bool:
// 		return nosql.Bool(v)
// 	case time.Time:
// 		return nosql.Time(v)
// 	case []byte:
// 		return nosql.Bytes(v)
// 	default:
// 		panic(fmt.Errorf("unsupported type: %T", v))
// 	}
// }
// func toBsonDoc(d nosql.Document) bson.M {
// 	fmt.Println("noms:toBsonDoc()")
// 	if d == nil {
// 		return nil
// 	}
// 	m := make(bson.M, len(d))
// 	for k, v := range d {
// 		m[k] = toBsonValue(v)
// 	}
// 	return m
// }
// func fromBsonDoc(d bson.M) nosql.Document {
// 	fmt.Println("noms:fromBsonDoc()")
// 	if d == nil {
// 		return nil
// 	}
// 	m := make(nosql.Document, len(d))
// 	for k, v := range d {
// 		m[k] = fromBsonValue(v)
// 	}
// 	return m
// }

// const idField = "_id"

// func (c *collection) getKey(m bson.M) nosql.Key {
// 	fmt.Println("noms:getKey()")
// 	if !c.compPK {
// 		// key field renamed to _id - just return it
// 		if v, ok := m[idField].(string); ok {
// 			return nosql.Key{v}
// 		}
// 		return nil
// 	}
// 	// key field computed from multiple source fields
// 	// get source fields from document in correct order
// 	key := make(nosql.Key, 0, len(c.primary.Fields))
// 	for _, f := range c.primary.Fields {
// 		s, _ := m[f].(string)
// 		key = append(key, s)
// 	}
// 	return key
// }

// func (c *collection) setKey(m bson.M, key nosql.Key) {
// 	fmt.Println("noms:setKey()")
// 	if !c.compPK {
// 		// delete source field, since we already added it as _id
// 		delete(m, c.primary.Fields[0])
// 	} else {
// 		for i, f := range c.primary.Fields {
// 			m[f] = string(key[i])
// 		}
// 	}
// }

// func (c *collection) convDoc(m bson.M) nosql.Document {
// 	if c.compPK {
// 		// key field computed from multiple source fields - remove it
// 		delete(m, idField)
// 	} else {
// 		// key field renamed - set correct name
// 		if v, ok := m[idField].(string); ok {
// 			delete(m, idField)
// 			m[c.primary.Fields[0]] = string(v)
// 		}
// 	}
// 	return fromBsonDoc(m)
// }

// func getOrGenID(key nosql.Key) (nosql.Key, string) {
// 	fmt.Println("noms:getOrGenID()")
// 	var mid string
// 	if key == nil {
// 		// TODO: maybe allow to pass custom key types as nosql.Key
// 		oid := objidString(bson.NewObjectId())
// 		mid = oid
// 		key = nosql.Key{oid}
// 	} else {
// 		mid = compKey(key)
// 	}
// 	return key, mid
// }

// func (c *collection) convIns(key nosql.Key, d nosql.Document) (nosql.Key, bson.M) {
// 	m := toBsonDoc(d)

// 	var mid string
// 	key, mid = getOrGenID(key)
// 	m[idField] = mid
// 	c.setKey(m, key)

// 	return key, m
// }

// func objidString(id bson.ObjectId) string {
// 	return base64.StdEncoding.EncodeToString([]byte(id))
// }

func compKey(key nosql.Key) string {
	if len(key) == 1 {
		return key[0]
	}
	return strings.Join(key, "")
}

// func buildFilters(filters []nosql.FieldFilter) bson.M {
// 	m := make(bson.M, len(filters))
// 	for _, f := range filters {
// 		name := strings.Join(f.Path, ".")
// 		v := toBsonValue(f.Value)
// 		if f.Filter == nosql.Equal {
// 			m[name] = v
// 			continue
// 		}
// 		var mf bson.M
// 		switch mp := m[name].(type) {
// 		case nil:
// 		case bson.M:
// 			mf = mp
// 		default:
// 			continue
// 		}
// 		if mf == nil {
// 			mf = make(bson.M)
// 		}
// 		switch f.Filter {
// 		case nosql.NotEqual:
// 			mf["$ne"] = v
// 		case nosql.GT:
// 			mf["$gt"] = v
// 		case nosql.GTE:
// 			mf["$gte"] = v
// 		case nosql.LT:
// 			mf["$lt"] = v
// 		case nosql.LTE:
// 			mf["$lte"] = v
// 		case nosql.Regexp:
// 			pattern, ok := f.Value.(nosql.String)
// 			if !ok {
// 				panic(fmt.Errorf("unsupported regexp argument: %v", f.Value))
// 			}
// 			mf["$regex"] = pattern
// 		default:
// 			panic(fmt.Errorf("unsupported filter: %v", f.Filter))
// 		}
// 		m[name] = mf
// 	}
// 	return m
// }

// func mergeFilters(dst, src bson.M) {
// 	for k, v := range src {
// 		dst[k] = v
// 	}
// }

func (q *Query) WithFields(filters ...nosql.FieldFilter) nosql.Query {
	// m := buildFilters(filters)
	// if q.query == nil {
	// 	q.query = m
	// } else {
	// 	mergeFilters(q.query, m)
	// }
	return q
}

func (q *Query) Limit(n int) nosql.Query {
	// q.limit = n
	return q
}

// func (q *Query) build() *mgo.Query {
// 	var m interface{}
// 	if q.query != nil {
// 		m = q.query
// 	}
// 	qu := q.c.c.Find(m)
// 	if q.limit > 0 {
// 		qu = qu.Limit(q.limit)
// 	}
// 	return qu
// }

func (q *Query) Count(ctx context.Context) (int64, error) {
	// n, err := q.build().Count()
	return int64(0), nil
}

func (q *Query) One(ctx context.Context) (nosql.Document, error) {
	// var m bson.M
	// err := q.build().One(&m)
	// if err == mgo.ErrNotFound {
	// 	return nil, nosql.ErrNotFound
	// } else if err != nil {
	// 	return nil, err
	// }
	// return q.c.convDoc(m), nil
	return nil, nil
}

func (q *Query) Iterate() nosql.DocIterator {
	// it := q.build().Iter()
	// return &Iterator{it: it, c: q.c}
	return nil
}

// type Iterator struct {
// 	c   *collection
// 	it  *mgo.Iter
// 	res bson.M
// }

// func (it *Iterator) Next(ctx context.Context) bool {
// 	it.res = make(bson.M)
// 	return it.it.Next(&it.res)
// }
// func (it *Iterator) Err() error {
// 	return it.it.Err()
// }
// func (it *Iterator) Close() error {
// 	return it.it.Close()
// }
// func (it *Iterator) Key() nosql.Key {
// 	return it.c.getKey(it.res)
// }
// func (it *Iterator) Doc() nosql.Document {
// 	return it.c.convDoc(it.res)
// }

type Delete struct {
	// col   *collection
	// query bson.M
}

func (d *Delete) WithFields(filters ...nosql.FieldFilter) nosql.Delete {
	// m := buildFilters(filters)
	// if d.query == nil {
	// 	d.query = m
	// } else {
	// 	mergeFilters(d.query, m)
	// }
	return d
}

func (d *Delete) Keys(keys ...nosql.Key) nosql.Delete {
	// if len(keys) == 0 {
	// 	return d
	// }
	// m := make(bson.M, 1)
	// if len(keys) == 1 {
	// 	m[idField] = compKey(keys[0])
	// } else {
	// 	ids := make([]string, 0, len(keys))
	// 	for _, k := range keys {
	// 		ids = append(ids, compKey(k))
	// 	}
	// 	m[idField] = bson.M{"$in": ids}
	// }
	// if d.query == nil {
	// 	d.query = m
	// } else {
	// 	mergeFilters(d.query, m)
	// }
	return d
}

func (d *Delete) Do(ctx context.Context) error {
	// var qu interface{}
	// if d.query != nil {
	// 	qu = d.query
	// }
	// _, err := d.col.c.RemoveAll(qu)
	return nil
}

// ----------------------------------------------------------------------------
// Update
// ----------------------------------------------------------------------------

type Update struct {
	col     string
	db      datas.Database
	dsName  string
	key     nosql.Key
	qValue  nQuad
	nValue  nNode
	changed bool
}

func (u *Update) Upsert(d nosql.Document) nosql.Update {
	fmt.Printf("noms::Update::Upsert() \n")

	fmt.Printf("noms::Update::Upsert() %+v\n", d)

	//TODO  - Find existing node in DB and check if update is required
	if u.col == "nodes" {
		val, _ := nodeDocToNoms(d)
		u.nValue = val
		fmt.Printf("nVALUE :: %+v\n", val)
	} else if u.col == "quads" {
		val, _ := quadDocToNoms(d)
		u.qValue = val
		// fmt.Printf("qVALUE :: %+v\n", u.qValue)
	}

	return u
}

func (u *Update) Inc(field string, dn int) nosql.Update {
	fmt.Printf("noms::Update::Inc() field: %s \n", field)

	if u.col == "quads" && field == "added" {
		u.qValue.Added += 1
		return u
	}
	// inc, _ := u.update["$inc"].(bson.M)
	// if inc == nil {
	// 	inc = make(bson.M)
	// }
	// inc[field] = dn
	// u.update["$inc"] = inc
	return u
}

func (u *Update) Push(field string, v nosql.Value) nosql.Update {
	fmt.Printf("noms::Update::Push() field: %s NOT IMPLEMENTED YET \n", field)
	return u
}

func (u *Update) Do(ctx context.Context) error {
	fmt.Printf("noms::Update::Do() \n")

	key := compKey(u.key)

	ds := u.db.GetDataset(u.dsName)

	if u.col == "quads" {

		np, err := marshal.Marshal(u.db, u.qValue)
		if err != nil {
			return fmt.Errorf("Could not marshal.Marshal(db, u.qValue): %s", err)
		}

		_, err = u.db.CommitValue(ds, getItems(ds).Edit().Set(types.String(key), np).Map())
		if err != nil {
			return fmt.Errorf("Error committing: %s", err)
		}
	} else if u.col == "nodes" {

		np, err := marshal.Marshal(u.db, u.nValue)
		if err != nil {
			return fmt.Errorf("Could not marshal.Marshal(db, u.nValue): %s", err)
		}

		_, err = u.db.CommitValue(ds, getItems(ds).Edit().Set(types.String(key), np).Map())
		if err != nil {
			return fmt.Errorf("Error committing: %s", err)
		}
	}

	return nil
}

func quadDocToNoms(d nosql.Document) (nQuad, error) {
	fmt.Println("noms:quadDocToNoms()")
	if d == nil {
		return nQuad{}, nil
	}

	var nq nQuad
	mapstructure.Decode(d, &nq)

	return nq, nil
}

func quadNomsToDoc(d nQuad) (nosql.Document, error) {
	fmt.Println("noms:quadDocToNoms()")

	m := make(nosql.Document, 5)

	m["subject"] = nosql.String(d.Subject)
	m["predicate"] = nosql.String(d.Predicate)
	m["object"] = nosql.String(d.Object)
	m["label"] = nosql.String(d.Label)
	m["added"] = nosql.Int(d.Added)

	return m, nil
}

func nodeDocToNoms(d nosql.Document) (nNode, error) {
	fmt.Println("noms:nodeDocToNoms()")
	var nn nNode

	if d == nil {
		return nn, nil
	}

	val, ok := d["value"]

	if !ok {
		return nn, fmt.Errorf("key value not present in Document for node")
	} else if len(val.(nosql.Document)) != 1 {
		return nn, fmt.Errorf("more than 1 value in Document for node")
	}

	for _, vl := range val.(nosql.Document) {
		switch v := vl.(type) {
		// case nil:
		// 	return nil
		// case nosql.Document:
		// 	return toBsonDoc(v)
		case nosql.String:
			nn.Type = "str"
			nn.Value = string(v)
		case nosql.Int:
			nn.Type = "int"
			nn.Value = int64(v)
		// case nosql.Float:
		// 	return float64(v)
		// case nosql.Bool:
		// 	return bool(v)
		// case nosql.Time:
		// 	return time.Time(v)
		// case nosql.Bytes:
		// 	return []byte(v)
		default:
			panic(fmt.Errorf("unsupported type: %T", v))
		}
	}

	return nn, nil
}

func nodeNomsToDoc(d nNode) (nosql.Document, error) {

	m := make(nosql.Document, 1)

	m["value"] = make(nosql.Document, 1)

	return m, nil
}

// func (db *DB) BatchInsert(col string) nosql.DocWriter {
// 	c := db.colls[col]
// 	return &inserter{col: &c}
// }

// const batchSize = 100

// type inserter struct {
// 	col   *collection
// 	buf   []interface{}
// 	ikeys []nosql.Key
// 	keys  []nosql.Key
// 	err   error
// }

// func (w *inserter) WriteDoc(ctx context.Context, key nosql.Key, d nosql.Document) error {
// 	if len(w.buf) >= batchSize {
// 		if err := w.Flush(ctx); err != nil {
// 			return err
// 		}
// 	}
// 	key, m := w.col.convIns(key, d)
// 	w.buf = append(w.buf, m)
// 	w.ikeys = append(w.ikeys, key)
// 	return nil
// }

// func (w *inserter) Flush(ctx context.Context) error {
// 	if len(w.buf) == 0 {
// 		return w.err
// 	}
// 	if err := w.col.c.Insert(w.buf...); err != nil {
// 		w.err = err
// 		return err
// 	}
// 	w.keys = append(w.keys, w.ikeys...)
// 	w.ikeys = w.ikeys[:0]
// 	w.buf = w.buf[:0]
// 	return w.err
// }

// func (w *inserter) Keys() []nosql.Key {
// 	return w.keys
// }

// func (w *inserter) Close() error {
// 	w.ikeys = nil
// 	w.buf = nil
// 	return w.err

// }
