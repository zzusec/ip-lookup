package datasets

import (
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

const xdbPoolSize = 4

// XDBSearcher makes an ip2region database usable from many goroutines. A
// Searcher keeps per-call state, so each lookup borrows one from a fixed
// pool. All file handles are opened up front, which keeps the value usable
// after the file on disk has been replaced.
type XDBSearcher struct {
	pool     chan *xdb.Searcher
	Version  *xdb.Version
	Segments int // number of address ranges in the file
}

// openXDB holds the content in memory when inMemory is set (fine for the
// 11 MB IPv4 file) and otherwise reads the file through a shared vector index.
func openXDB(path string, inMemory bool) (*XDBSearcher, error) {
	if err := xdb.VerifyFromFile(path); err != nil {
		return nil, err
	}
	h, err := xdb.LoadHeaderFromFile(path)
	if err != nil {
		return nil, err
	}
	ver, err := xdb.VersionFromHeader(h)
	if err != nil {
		return nil, err
	}
	var content, vIndex []byte
	if inMemory {
		content, err = xdb.LoadContentFromFile(path)
	} else {
		vIndex, err = xdb.LoadVectorIndexFromFile(path)
	}
	if err != nil {
		return nil, err
	}
	s := &XDBSearcher{pool: make(chan *xdb.Searcher, xdbPoolSize), Version: ver}
	if h.EndIndexPtr >= h.StartIndexPtr {
		s.Segments = int(h.EndIndexPtr-h.StartIndexPtr)/ver.SegmentIndexSize + 1
	}
	for range xdbPoolSize {
		var se *xdb.Searcher
		if inMemory {
			se, err = xdb.NewWithBuffer(ver, content)
		} else {
			se, err = xdb.NewWithVectorIndex(ver, path, vIndex)
		}
		if err != nil {
			for len(s.pool) > 0 {
				(<-s.pool).Close()
			}
			return nil, err
		}
		s.pool <- se
	}
	return s, nil
}

// Search returns the raw "country|region|city|isp|cc" record, or "" when unknown.
// ip must have the length of the database's address family.
func (s *XDBSearcher) Search(ip []byte) (string, error) {
	se := <-s.pool
	defer func() { s.pool <- se }()
	return se.Search(ip)
}
