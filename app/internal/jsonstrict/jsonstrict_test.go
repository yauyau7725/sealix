package jsonstrict

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "objek valid", input: `{"a":1}`, wantErr: false},
		{name: "key duplikat", input: `{"a":1,"a":2}`, wantErr: true},
		{name: "duplikat bersarang", input: `{"x":{"a":1,"a":2}}`, wantErr: true},
		{name: "data sisa", input: `{"a":1} {}`, wantErr: true},
		{name: "koma di akhir", input: `{"a":1,}`, wantErr: true},
		{name: "string", input: `"halo"`, wantErr: false},
		{name: "angka", input: `123`, wantErr: false},
		{name: "bool", input: `true`, wantErr: false},
		{name: "null", input: `null`, wantErr: false},
		{name: "dua nilai", input: `1 2`, wantErr: true},
		{name: "objek kosong", input: `{}`, wantErr: false},
		{name: "objek bersarang", input: `{"a":{"b":2},"c":"x"}`, wantErr: false},
		{name: "key beda huruf", input: `{"a":1,"A":2}`, wantErr: false},
		{name: "array kosong", input: `[]`, wantErr: false},
		{name: "array campuran", input: `[1,"a",null,true]`, wantErr: false},
		{name: "duplikat dalam array", input: `[{"a":1,"a":2}]`, wantErr: true},
		{name: "koma di akhir array", input: `[1,]`, wantErr: true},
		{name: "BOM di awal", input: "\xef\xbb\xbf{}", wantErr: true},
		{name: "UTF-8 rusak", input: "{\"a\":\"\xff\"}", wantErr: true},
		{name: "UTF-8 valid non-ASCII", input: `{"a":"é"}`, wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.input))
			if (err != nil) != tc.wantErr {
				t.Errorf("Parse(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestParseDepth(t *testing.T) {
	validInput := strings.Repeat("[", 32) + strings.Repeat("]", 32)
	if _, err := Parse([]byte(validInput)); err != nil {
		t.Errorf("Parse dengan kedalaman n=32 seharusnya lolos, tetapi mendapat error: %v", err)
	}

	invalidInput := strings.Repeat("[", 33) + strings.Repeat("]", 33)
	if _, err := Parse([]byte(invalidInput)); err == nil {
		t.Errorf("Parse dengan kedalaman n=33 seharusnya gagal, tetapi tanpa error")
	}
}

func TestValueInt(t *testing.T) {
	tests := []struct {
		name    string
		v       Value
		want    int64
		wantErr bool
	}{
		{name: "nol", v: Value{Kind: KindNumber, Num: "0"}, want: 0, wantErr: false},
		{name: "positif", v: Value{Kind: KindNumber, Num: "42"}, want: 42, wantErr: false},
		{name: "batas aman maksimal", v: Value{Kind: KindNumber, Num: "9007199254740991"}, want: 9007199254740991, wantErr: false},
		{name: "melebihi batas aman", v: Value{Kind: KindNumber, Num: "9007199254740992"}, wantErr: true},
		{name: "desimal", v: Value{Kind: KindNumber, Num: "1.0"}, wantErr: true},
		{name: "eksponen", v: Value{Kind: KindNumber, Num: "1e3"}, wantErr: true},
		{name: "nol negatif", v: Value{Kind: KindNumber, Num: "-0"}, wantErr: true},
		{name: "negatif", v: Value{Kind: KindNumber, Num: "-1"}, wantErr: true},
		{name: "nol di depan", v: Value{Kind: KindNumber, Num: "01"}, wantErr: true},
		{name: "tanda plus", v: Value{Kind: KindNumber, Num: "+1"}, wantErr: true},
		{name: "string angka kosong", v: Value{Kind: KindNumber, Num: ""}, wantErr: true},
		{name: "bukan angka bool", v: Value{Kind: KindBool, Bool: true}, wantErr: true},
		{name: "bukan angka string", v: Value{Kind: KindString, Str: "1"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.v.Int()
			if (err != nil) != tc.wantErr {
				t.Errorf("Int() error = %v, wantErr = %v", err, tc.wantErr)
				return
			}
			if err == nil && got != tc.want {
				t.Errorf("Int() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestValueString(t *testing.T) {
	tests := []struct {
		name    string
		v       Value
		want    string
		wantErr bool
	}{
		{name: "string valid", v: Value{Kind: KindString, Str: "halo"}, want: "halo", wantErr: false},
		{name: "string kosong", v: Value{Kind: KindString, Str: ""}, want: "", wantErr: false},
		{name: "null", v: Value{Kind: KindNull}, wantErr: true},
		{name: "angka", v: Value{Kind: KindNumber, Num: "1"}, wantErr: true},
		{name: "bool", v: Value{Kind: KindBool, Bool: true}, wantErr: true},
		{name: "array kosong", v: Value{Kind: KindArray}, wantErr: true},
		{name: "objek kosong", v: Value{Kind: KindObject, Obj: &Object{}}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.v.String()
			if (err != nil) != tc.wantErr {
				t.Errorf("String() error = %v, wantErr = %v", err, tc.wantErr)
				return
			}
			if err == nil && got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValueArray(t *testing.T) {
	vTwo := Value{
		Kind: KindArray,
		Arr:  []Value{{Kind: KindNumber, Num: "1"}, {Kind: KindString, Str: "dua"}},
	}
	got, err := vTwo.Array()
	if err != nil {
		t.Fatalf("Array() dengan 2 elemen tidak seharusnya galat: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("panjang Array() = %d, want 2", len(got))
	}

	vEmpty := Value{Kind: KindArray}
	gotEmpty, err := vEmpty.Array()
	if err != nil {
		t.Fatalf("Array() kosong tidak seharusnya galat: %v", err)
	}
	if len(gotEmpty) != 0 {
		t.Errorf("panjang Array() kosong = %d, want 0", len(gotEmpty))
	}

	vStr := Value{Kind: KindString, Str: "bukan array"}
	if _, err := vStr.Array(); err == nil {
		t.Errorf("Array() pada KindString seharusnya galat")
	}

	vObj := Value{Kind: KindObject, Obj: &Object{}}
	if _, err := vObj.Array(); err == nil {
		t.Errorf("Array() pada KindObject seharusnya galat")
	}
}

func TestValueObject(t *testing.T) {
	vObj := Value{
		Kind: KindObject,
		Obj: &Object{
			Keys:   []string{"a"},
			Values: map[string]Value{"a": {Kind: KindNumber, Num: "1"}},
		},
	}
	got, err := vObj.Object()
	if err != nil {
		t.Fatalf("Object() valid tidak seharusnya galat: %v", err)
	}
	if got == nil {
		t.Errorf("Object() mengembalikan pointer nil")
	}

	vArr := Value{Kind: KindArray}
	if _, err := vArr.Object(); err == nil {
		t.Errorf("Object() pada KindArray seharusnya galat")
	}

	vNull := Value{Kind: KindNull}
	if _, err := vNull.Object(); err == nil {
		t.Errorf("Object() pada KindNull seharusnya galat")
	}
}

func TestObjectExactly(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		fields  []string
		wantErr bool
	}{
		{name: "sama persis", input: `{"a":1,"b":2}`, fields: []string{"a", "b"}, wantErr: false},
		{name: "urutan beda", input: `{"a":1,"b":2}`, fields: []string{"b", "a"}, wantErr: false},
		{name: "objek kosong", input: `{}`, fields: nil, wantErr: false},
		{name: "key berlebih", input: `{"a":1,"b":2}`, fields: []string{"a"}, wantErr: true},
		{name: "key kurang", input: `{"a":1,"b":2}`, fields: []string{"a", "b", "c"}, wantErr: true},
		{name: "beda huruf", input: `{"a":1,"b":2}`, fields: []string{"A", "B"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Parse([]byte(tc.input))
			if err != nil {
				t.Fatalf("Parse(%q) gagal: %v", tc.input, err)
			}
			obj, err := v.Object()
			if err != nil {
				t.Fatalf("Object() gagal: %v", err)
			}

			err = obj.Exactly(tc.fields...)
			if (err != nil) != tc.wantErr {
				t.Errorf("Exactly(%v) error = %v, wantErr = %v", tc.fields, err, tc.wantErr)
			}
		})
	}
}
