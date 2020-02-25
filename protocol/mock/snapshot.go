// Code generated by mockery v1.0.0. DO NOT EDIT.

package mock

import flow "github.com/dapperlabs/flow-go/model/flow"
import mock "github.com/stretchr/testify/mock"

// Snapshot is an autogenerated mock type for the Snapshot type
type Snapshot struct {
	mock.Mock
}

// Clusters provides a mock function with given fields:
func (_m *Snapshot) Clusters() (*flow.ClusterList, error) {
	ret := _m.Called()

	var r0 *flow.ClusterList
	if rf, ok := ret.Get(0).(func() *flow.ClusterList); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*flow.ClusterList)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Head provides a mock function with given fields:
func (_m *Snapshot) Head() (*flow.Header, error) {
	ret := _m.Called()

	var r0 *flow.Header
	if rf, ok := ret.Get(0).(func() *flow.Header); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*flow.Header)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Identities provides a mock function with given fields: filters
func (_m *Snapshot) Identities(filters ...flow.IdentityFilter) (flow.IdentityList, error) {
	_va := make([]interface{}, len(filters))
	for _i := range filters {
		_va[_i] = filters[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 flow.IdentityList
	if rf, ok := ret.Get(0).(func(...flow.IdentityFilter) flow.IdentityList); ok {
		r0 = rf(filters...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(flow.IdentityList)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(...flow.IdentityFilter) error); ok {
		r1 = rf(filters...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Identity provides a mock function with given fields: nodeID
func (_m *Snapshot) Identity(nodeID flow.Identifier) (*flow.Identity, error) {
	ret := _m.Called(nodeID)

	var r0 *flow.Identity
	if rf, ok := ret.Get(0).(func(flow.Identifier) *flow.Identity); ok {
		r0 = rf(nodeID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*flow.Identity)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(flow.Identifier) error); ok {
		r1 = rf(nodeID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Seal provides a mock function with given fields:
func (_m *Snapshot) Seal() (flow.Seal, error) {
	ret := _m.Called()

	var r0 flow.Seal
	if rf, ok := ret.Get(0).(func() flow.Seal); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(flow.Seal)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StateCommitment provides a mock function with given fields:
func (_m *Snapshot) StateCommitment() ([]byte, error) {
	ret := _m.Called()

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
