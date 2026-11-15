package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"
)

const (
	MaxDepth   = 32
	MaxSafeInt = 9007199254740991
)

var intPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type Kind int

const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

type Value struct {
	Kind Kind
	Str  string
	Num  string
	Bool bool
	Arr  []Value
	Obj  *Object
}

type Object struct {
	Keys   []string
	Values map[string]Value
}

func Parse(data []byte) (Value, error) {
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return Value{}, errors.New("BOM tidak diperbolehkan")
	}
	if !utf8.Valid(data) {
		return Value{}, errors.New("masukan bukan UTF-8 yang valid")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	val, err := parseValue(dec, 0)
	if err != nil {
		return Value{}, err
	}

	if _, err := dec.Token(); err != io.EOF {
		return Value{}, errors.New("terdapat data sisa setelah nilai utama")
	}

	return val, nil
}

func parseValue(dec *json.Decoder, depth int) (Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return Value{}, err
	}

	switch t := tok.(type) {
	case string:
		return Value{Kind: KindString, Str: t}, nil
	case json.Number:
		return Value{Kind: KindNumber, Num: t.String()}, nil
	case bool:
		return Value{Kind: KindBool, Bool: t}, nil
	case nil:
		return Value{Kind: KindNull}, nil
	case json.Delim:
		if t == '{' {
			return parseObject(dec, depth)
		}
		if t == '[' {
			return parseArray(dec, depth)
		}
		return Value{}, fmt.Errorf("delimiter tak terduga %q", t)
	default:
		return Value{}, fmt.Errorf("token tidak dikenal: %T", tok)
	}
}

func parseObject(dec *json.Decoder, depth int) (Value, error) {
	if depth+1 > MaxDepth {
		return Value{}, fmt.Errorf("kedalaman melebihi batas maksimal %d", MaxDepth)
	}
	obj := &Object{Values: map[string]Value{}}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return Value{}, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return Value{}, fmt.Errorf("key objek harus berupa string, mendapat %T", keyTok)
		}
		if _, exists := obj.Values[key]; exists {
			return Value{}, fmt.Errorf("key duplikat: %q", key)
		}

		val, err := parseValue(dec, depth+1)
		if err != nil {
			return Value{}, err
		}
		obj.Values[key] = val
		obj.Keys = append(obj.Keys, key)
	}
	if _, err := dec.Token(); err != nil {
		return Value{}, err
	}

	return Value{Kind: KindObject, Obj: obj}, nil
}

func parseArray(dec *json.Decoder, depth int) (Value, error) {
	if depth+1 > MaxDepth {
		return Value{}, fmt.Errorf("kedalaman melebihi batas maksimal %d", MaxDepth)
	}

	var arr []Value
	for dec.More() {
		val, err := parseValue(dec, depth+1)
		if err != nil {
			return Value{}, err
		}
		arr = append(arr, val)
	}
	if _, err := dec.Token(); err != nil {
		return Value{}, err
	}

	return Value{Kind: KindArray, Arr: arr}, nil
}

func (v Value) Int() (int64, error) {
	if v.Kind != KindNumber {
		return 0, errors.New("nilai bukan angka")
	}
	if !intPattern.MatchString(v.Num) {
		return 0, fmt.Errorf("format bilangan bulat tidak valid: %q", v.Num)
	}
	n, err := strconv.ParseInt(v.Num, 10, 64)
	if err != nil {
		return 0, err
	}
	if n > MaxSafeInt {
		return 0, fmt.Errorf("bilangan melebihi batas aman maksimal %d", MaxSafeInt)
	}
	return n, nil
}

func (v Value) String() (string, error) {
	if v.Kind != KindString {
		return "", errors.New("nilai bukan string")
	}
	return v.Str, nil
}

func (v Value) Array() ([]Value, error) {
	if v.Kind != KindArray {
		return nil, errors.New("nilai bukan Array")
	}
	return v.Arr, nil
}

func (v Value) Object() (*Object, error) {
	if v.Kind != KindObject {
		return nil, errors.New("nilai bukan Object")
	}
	return v.Obj, nil
}

func (o *Object) Exactly(fields ...string) error {
	var missing []string
	want := make(map[string]bool, len(fields))
	for _, f := range fields {
		want[f] = true
		if _, exists := o.Values[f]; !exists {
			missing = append(missing, f)
		}
	}

	var extra []string
	for _, k := range o.Keys {
		if !want[k] {
			extra = append(extra, k)
		}
	}

	if len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("field kurang: %v, field berlebih: %v", missing, extra)
	}
	return nil
}
