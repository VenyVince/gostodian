// Package pipeline는 점검 머신 설정의 서비스 순서를 다룬다.
// 서비스 이름은 이 패키지에 없다.
package pipeline

import "strings"

// StopOrder는 설정 목록의 순서다.
// 앞뒤 공백은 빼고, 빈 항목은 뺀다. 입력 슬라이스는 바꾸지 않는다.
func StopOrder(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

// StartOrder는 StopOrder의 역순이다.
func StartOrder(names []string) []string {
	stop := StopOrder(names)
	out := make([]string, len(stop))
	for i, name := range stop {
		out[len(stop)-1-i] = name
	}
	return out
}
