package pipeline

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStopOrderKeepsConfigOrder(t *testing.T) {
	in := []string{" a ", "", "b", "  ", "c"}
	got := StopOrder(in)
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stop = %#v", got)
	}
	if !reflect.DeepEqual(in, []string{" a ", "", "b", "  ", "c"}) {
		t.Fatalf("input changed: %#v", in)
	}
}

func TestStartOrderIsReverse(t *testing.T) {
	got := StartOrder([]string{"a", "b", "c"})
	want := []string{"c", "b", "a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("start = %#v", got)
	}
}

func TestEmptyOrder(t *testing.T) {
	if len(StopOrder(nil)) != 0 || len(StartOrder(nil)) != 0 {
		t.Fatal("nil list was not empty")
	}
	if len(StopOrder([]string{" ", ""})) != 0 || len(StartOrder([]string{" "})) != 0 {
		t.Fatal("blank list was not empty")
	}
}

func TestExampleHasNoServiceNames(t *testing.T) {
	path := filepath.Join("..", "..", "config", "config.yaml.example")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Pipeline struct {
			DockerOrder []string `yaml:"docker_order"`
		} `yaml:"pipeline"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Pipeline.DockerOrder) != 0 {
		t.Fatalf("docker_order = %#v", cfg.Pipeline.DockerOrder)
	}
}

func TestProductionCodeHasNoServiceNames(t *testing.T) {
	root := filepath.Join("..", "..")
	forbidden := []string{"traefik", "minio", "authentik", "redis", "postgres"}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "LocalDoc", "Doc":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := strings.ToLower(string(body))
		for _, name := range forbidden {
			if strings.Contains(text, name) {
				t.Errorf("%s contains %s", path, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
