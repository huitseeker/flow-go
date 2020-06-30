// Code generated by mockery v1.0.0. DO NOT EDIT.

package mock

import (
	metrics "github.com/dapperlabs/flow-go/module/metrics"
	mock "github.com/stretchr/testify/mock"
)

// MempoolMetrics is an autogenerated mock type for the MempoolMetrics type
type MempoolMetrics struct {
	mock.Mock
}

// MempoolEntries provides a mock function with given fields: resource, entries
func (_m *MempoolMetrics) MempoolEntries(resource string, entries uint) {
	_m.Called(resource, entries)
}

// Register provides a mock function with given fields: resource, entriesFunc
func (_m *MempoolMetrics) Register(resource string, entriesFunc metrics.EntriesFunc) error {
	ret := _m.Called(resource, entriesFunc)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, metrics.EntriesFunc) error); ok {
		r0 = rf(resource, entriesFunc)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
