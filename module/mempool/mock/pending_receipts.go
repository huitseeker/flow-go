// Code generated by mockery v1.0.0. DO NOT EDIT.

package mempool

import (
	flow "github.com/onflow/flow-go/model/flow"

	mock "github.com/stretchr/testify/mock"
)

// PendingReceipts is an autogenerated mock type for the PendingReceipts type
type PendingReceipts struct {
	mock.Mock
}

// Add provides a mock function with given fields: receipt
func (_m *PendingReceipts) Add(receipt *flow.ExecutionReceipt) bool {
	ret := _m.Called(receipt)

	var r0 bool
	if rf, ok := ret.Get(0).(func(*flow.ExecutionReceipt) bool); ok {
		r0 = rf(receipt)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// ByPreviousResultID provides a mock function with given fields: previousReusltID
func (_m *PendingReceipts) ByPreviousResultID(previousReusltID flow.Identifier) []*flow.ExecutionReceipt {
	ret := _m.Called(previousReusltID)

	var r0 []*flow.ExecutionReceipt
	if rf, ok := ret.Get(0).(func(flow.Identifier) []*flow.ExecutionReceipt); ok {
		r0 = rf(previousReusltID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*flow.ExecutionReceipt)
		}
	}

	return r0
}

// Rem provides a mock function with given fields: receiptID
func (_m *PendingReceipts) Rem(receiptID flow.Identifier) bool {
	ret := _m.Called(receiptID)

	var r0 bool
	if rf, ok := ret.Get(0).(func(flow.Identifier) bool); ok {
		r0 = rf(receiptID)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Size provides a mock function with given fields:
func (_m *PendingReceipts) Size() uint {
	ret := _m.Called()

	var r0 uint
	if rf, ok := ret.Get(0).(func() uint); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint)
	}

	return r0
}