package vpn

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrRequired는 설정된 VPN 인터페이스가 없거나 내려가 있는 경우다.
// SSH 접속 전에 반환한다.
var ErrRequired = errors.New("vpn_required")

var listInterfaces = net.Interfaces

// Check는 name이 비어 있으면 검사하지 않는다.
// 이름이 있으면 그 인터페이스가 올라와 있을 때만 nil을 반환한다.
func Check(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	ifaces, err := listInterfaces()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrRequired, name)
	}
	for _, iface := range ifaces {
		if iface.Name != name {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			return fmt.Errorf("%w: %s is down", ErrRequired, name)
		}
		return nil
	}
	return fmt.Errorf("%w: %s is absent", ErrRequired, name)
}
