package ssh

import (
	"errors"
	"strings"
	"testing"
)

func TestAuthorizedKeysOptions(t *testing.T) {
	got, err := AuthorizedKeysOptions("10.8.0.2")
	if err != nil {
		t.Fatal(err)
	}
	want := `restrict,from="10.8.0.2",command="/usr/local/bin/gostodian-gate"`
	if got != want {
		t.Fatalf("options = %q", got)
	}
	if !strings.Contains(got, `command="`+GatePath+`"`) {
		t.Fatalf("options = %q", got)
	}
}

func TestAuthorizedKeysOptionsRejectsUnsafeIP(t *testing.T) {
	for _, ip := range []string{
		"",
		"10.8.0.2/32",
		"10.8.0.2,10.8.0.3",
		`10.8.0.2",command="/bin/sh`,
		"not-an-ip",
		"*",
		" 10.8.0.2",
	} {
		if _, err := AuthorizedKeysOptions(ip); err == nil {
			t.Fatalf("accepted %q", ip)
		}
	}
}

func TestAdmitRunsGateOnlyFromAllowedIP(t *testing.T) {
	command, original, err := Admit("10.8.0.2", "10.8.0.2", StatusCommand)
	if err != nil {
		t.Fatal(err)
	}
	if command != GatePath || original != StatusCommand {
		t.Fatalf("command = %q original = %q", command, original)
	}
	if command == original || strings.ContainsAny(command, " \t\"'`$&|;<>") {
		t.Fatalf("executed command = %q", command)
	}
}

func TestAdmitSkipsGateFromOtherIP(t *testing.T) {
	command, original, err := Admit("10.8.0.2", "203.0.113.5", StatusCommand)
	if !errors.Is(err, ErrSourceDenied) {
		t.Fatalf("error = %v", err)
	}
	if command != "" || original != "" {
		t.Fatalf("command = %q original = %q", command, original)
	}
}

func TestAdmitDoesNotExecuteRequestedCommand(t *testing.T) {
	requested := `sh -c "rm -rf /"`
	command, original, err := Admit("10.8.0.2", "10.8.0.2", requested)
	if err != nil {
		t.Fatal(err)
	}
	if command != GatePath {
		t.Fatalf("command = %q", command)
	}
	if original != requested || strings.Contains(command, requested) {
		t.Fatalf("command = %q original = %q", command, original)
	}
}
