package datasets

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/zzusec/ip-lookup/internal/cidr"
)

// Loaded is one dataset ready for lookups; one of its lookup fields is set.
// It holds no resources that need closing: mappings and file handles of a
// replaced value are released by the garbage collector once no lookup uses it.
type Loaded struct {
	MMDB  *maxminddb.Reader
	XDB   *XDBSearcher
	List  *cidr.Set
	ASN   map[uint32]string // asns.csv: class; tag lists: ""; ASN-DROP: AS name
	Count int
}

// load parses the downloaded parts of spec. Paths are in URL order.
func load(spec Spec, paths []string) (*Loaded, error) {
	switch spec.Format {
	case MMDB, MMDBGzip:
		db, err := maxminddb.Open(paths[0])
		if err != nil {
			return nil, err
		}
		// Reader.Verify walks the whole file and allocates gigabytes on a
		// 100 MB database, too much for a small host; a probe lookup catches
		// truncated or foreign files instead.
		var probe any
		if err := db.Lookup(netip.MustParseAddr("1.1.1.1")).Decode(&probe); err != nil || db.Metadata.NodeCount == 0 {
			db.Close()
			return nil, fmt.Errorf("probe lookup: %v (nodes %d)", err, db.Metadata.NodeCount)
		}
		return &Loaded{MMDB: db, Count: int(db.Metadata.NodeCount)}, nil
	case XDB:
		s, err := openXDB(paths[0], s4(spec))
		if err != nil {
			return nil, err
		}
		return &Loaded{XDB: s, Count: s.Segments}, nil
	case ASNCSV, ASNTag, ASNDrop:
		m, err := readASNs(spec.Format, paths)
		if err != nil {
			return nil, err
		}
		return &Loaded{ASN: m, Count: len(m)}, nil
	}
	b := cidr.NewBuilder()
	n := 0
	read := func(r io.Reader) error {
		c, err := parseList(spec.Format, spec.Tag, r, b)
		n += c
		return err
	}
	if spec.Static != "" {
		if err := read(strings.NewReader(spec.Static)); err != nil {
			return nil, err
		}
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		err = read(bufio.NewReader(f))
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if n == 0 {
		return nil, errEmpty
	}
	return &Loaded{List: b.Build(), Count: n}, nil
}

// s4 keeps the IPv4 ip2region database (about 11 MB) in memory.
func s4(spec Spec) bool { return !strings.Contains(spec.ID, "v6") }

// readASNs keeps only what classification needs: for asns.csv the class of
// ASes whose class is known (about 11k of 120k rows), for tag lists the AS
// numbers, for ASN-DROP the AS names.
func readASNs(f Format, paths []string) (map[uint32]string, error) {
	m := map[uint32]string{}
	for _, p := range paths {
		fh, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		err = func() error {
			defer fh.Close()
			if f == ASNDrop {
				dec := json.NewDecoder(bufio.NewReader(fh))
				for {
					var e struct {
						ASN    uint32 `json:"asn"`
						ASName string `json:"asname"`
					}
					if err := dec.Decode(&e); err == io.EOF {
						return nil
					} else if err != nil {
						return err
					}
					if e.ASN != 0 {
						m[e.ASN] = e.ASName
					}
				}
			}
			r := csv.NewReader(bufio.NewReader(fh))
			r.FieldsPerRecord = -1
			r.ReuseRecord = true
			for {
				rec, err := r.Read()
				if err == io.EOF {
					return nil
				}
				if err != nil {
					return err
				}
				asn, ok := parseASN(rec[0])
				switch {
				case !ok: // header row
				case f == ASNTag:
					m[asn] = ""
				case len(rec) >= 3 && rec[2] != "Unknown" && rec[2] != "":
					m[asn] = strings.Clone(rec[2])
				}
			}
		}()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if len(m) == 0 {
		return nil, errEmpty
	}
	return m, nil
}

func parseASN(s string) (uint32, bool) {
	s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS")
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil && n > 0
}

// gunzip decompresses src into dst.
func gunzip(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(bufio.NewReader(in))
	if err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, zr); err != nil {
		out.Close()
		return errors.Join(err, os.Remove(dst))
	}
	return out.Close()
}
