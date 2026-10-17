package vpn

import (
	"errors"
	"net"
	"testing"
)

func TestCheckEmptySkipsLookup(t *testing.T) {
	prev := listInterfaces
	t.Cleanup(func() { listInterfaces = prev })
	listInterfaces = func() ([]net.Interface, error) {
		t.Fatal("empty interface still looked up interfaces")
		return nil, nil
	}
	if err := Check("  "); err != nil {
		t.Fatal(err)
	}
}

func TestCheckDownOrAbsent(t *testing.T) {
	prev := listInterfaces
	t.Cleanup(func() { listInterfaces = prev })
	listInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "wg0", Flags: 0}}, nil
	}
	if err := Check("wg0"); !errors.Is(err, ErrRequired) {
		t.Fatalf("down = %v", err)
	}

	listInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "eth0", Flags: net.FlagUp}}, nil
	}
	if err := Check("wg0"); !errors.Is(err, ErrRequired) {
		t.Fatalf("absent = %v", err)
	}
}

func TestCheckUp(t *testing.T) {
	prev := listInterfaces
	t.Cleanup(func() { listInterfaces = prev })
	listInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "wg0", Flags: net.FlagUp}}, nil
	}
	if err := Check("wg0"); err != nil {
		t.Fatal(err)
	}
}
