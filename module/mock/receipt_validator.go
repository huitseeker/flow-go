// Code generated by mockery v1.0.0. DO NOT EDIT.

package mock

import (
	flow "github.com/onflow/flow-go/model/flow"
	mock "github.com/stretchr/testify/mock"
)

// ReceiptValidator is an autogenerated mock type for the ReceiptValidator type
type ReceiptValidator struct {
	mock.Mock
}

// Validate provides a mock function with given fields: receipt
func (_m *ReceiptValidator) Validate(receipt *flow.ExecutionReceipt) error {
	ret := _m.Called(receipt)

	var r0 error
	if rf, ok := ret.Get(0).(func(*flow.ExecutionReceipt) error); ok {
		r0 = rf(receipt)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}