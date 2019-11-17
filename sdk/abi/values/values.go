package values

type Value interface {
	isValue()
}

type Void struct{}

func (Void) isValue() {}

type Nil struct{}

func (Nil) isValue() {}

type Bool bool

func (Bool) isValue() {}

type String string

func (String) isValue() {}

type Bytes []byte

func (Bytes) isValue() {}

// TODO: use big.Int to represent Int value
type Int int

func (Int) isValue() {}

type Int8 int8

func (Int8) isValue() {}

type Int16 int16

func (Int16) isValue() {}

type Int32 int32

func (Int32) isValue() {}

type Int64 int64

func (Int64) isValue() {}

type Uint8 uint8

func (Uint8) isValue() {}

type Uint16 uint16

func (Uint16) isValue() {}

type Uint32 uint32

func (Uint32) isValue() {}

type Uint64 uint64

func (Uint64) isValue() {}

type VariableSizedArray []Value

func (VariableSizedArray) isValue() {}

type ConstantSizedArray []Value

func (ConstantSizedArray) isValue() {}

type Dictionary []KeyValuePair

func (Dictionary) isValue() {}

type KeyValuePair struct {
	Key   Value
	Value Value
}

type Event struct {
	// TODO: is the Identifier field needed here?
	Identifier string
	Fields     []Value
}

type Composite struct {
	Fields []Value
}

func (Composite) isValue() {}

func (Event) isValue() {}

type Address [20]byte

func (Address) isValue() {}

func BytesToAddress(b []byte) Address {
	var a Address
	copy(a[:], b)
	return a
}
