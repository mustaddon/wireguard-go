//go:build !linux

package device

import (
	"github.com/mustaddon/wireguard-go/conn"
	"github.com/mustaddon/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
