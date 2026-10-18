package ssh

import (
	"errors"
	"net"
	"strings"
)

// GatePath는 홈랩 authorized_keys의 command=가 고정하는 실행 파일이다.
// 이 저장소는 그 줄을 홈랩에 등록하지 않는다.
const GatePath = "/usr/local/bin/gostodian-gate"

// ErrSourceDenied는 from=에 없는 주소라 게이트를 실행하지 않는 경우다.
var ErrSourceDenied = errors.New("source_denied")

// AuthorizedKeysOptions는 restrict, from, command만 담은 옵션이다.
// vpnIP는 점검 머신 VPN 주소 하나다. 공개키 본문은 포함하지 않는다.
func AuthorizedKeysOptions(vpnIP string) (string, error) {
	ip := net.ParseIP(vpnIP)
	if ip == nil || vpnIP != ip.String() || strings.ContainsAny(vpnIP, " \t\"',") {
		return "", errors.New("invalid vpn ip")
	}
	return `restrict,from="` + vpnIP + `",command="` + GatePath + `"`, nil
}

// Admit은 from=과 command=이 기대하는 판정이다.
// 허용된 주소가 아니면 게이트를 실행하지 않는다.
// 실행 파일은 GatePath뿐이고, 클라이언트가 보낸 문자열은 original로만 남는다.
func Admit(allowedIP, sourceIP, requested string) (command, original string, err error) {
	if !sameIP(allowedIP, sourceIP) {
		return "", "", ErrSourceDenied
	}
	return GatePath, requested, nil
}

func sameIP(allowed, source string) bool {
	a := net.ParseIP(allowed)
	b := net.ParseIP(source)
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}
