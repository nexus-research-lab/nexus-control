package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestEnv(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseEnvBytes(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		env    map[string]string
		want   map[string]string
		hasErr bool
	}{
		{name: "basic", raw: "FOO=bar\nBAZ=123\n", want: map[string]string{"FOO": "bar", "BAZ": "123"}},
		{name: "comments", raw: "# 这是注释\nFOO=bar\n# 另一条注释\nBAZ=qux\n", want: map[string]string{"FOO": "bar", "BAZ": "qux"}},
		{name: "inline comments", raw: "FOO=bar # 这是一个注释\n", want: map[string]string{"FOO": "bar"}},
		{name: "single quoted", raw: "FOO='hello world'\n", want: map[string]string{"FOO": "hello world"}},
		{name: "double quoted", raw: "FOO=\"hello world\"\n", want: map[string]string{"FOO": "hello world"}},
		{name: "double quoted escapes", raw: `FOO="line1\nline2"` + "\n", want: map[string]string{"FOO": "line1\nline2"}},
		{name: "export prefix", raw: "export FOO=bar\n", want: map[string]string{"FOO": "bar"}},
		{name: "blank lines", raw: "\n\nFOO=bar\n\nBAZ=qux\n\n", want: map[string]string{"FOO": "bar", "BAZ": "qux"}},
		{
			name: "empty value before comment and statement",
			raw:  "WORKSPACE_PATH=\n# Browser Login\nHOST=0.0.0.0\n",
			want: map[string]string{"WORKSPACE_PATH": "", "HOST": "0.0.0.0"},
		},
		{name: "var expansion", raw: "BASE=/opt\nPATH=${BASE}/bin\n", want: map[string]string{"BASE": "/opt", "PATH": "/opt/bin"}},
		{
			name: "simple var expansion",
			raw:  "URL=\"https://$NEXUS_TEST_EXT/api\"\n",
			env:  map[string]string{"NEXUS_TEST_EXT": "external"},
			want: map[string]string{"URL": "https://external/api"},
		},
		{name: "windows line endings", raw: "FOO=bar\r\nBAZ=qux\r\n", want: map[string]string{"FOO": "bar", "BAZ": "qux"}},
		{name: "escaped dollar", raw: `FOO=\${BAR}` + "\n", want: map[string]string{"FOO": "${BAR}"}},
		{name: "yaml colon", raw: "FOO: bar\n", want: map[string]string{"FOO": "bar"}},
		{name: "unterminated quote", raw: `FOO="unterminated` + "\n", hasErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for key, value := range test.env {
				t.Setenv(key, value)
			}
			got, err := parseEnvBytes([]byte(test.raw))
			if test.hasErr {
				if err == nil {
					t.Fatal("parseEnvBytes() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseEnvBytes() error = %v", err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("parseEnvBytes() = %#v, want %#v", got, test.want)
			}
			for key, want := range test.want {
				if got[key] != want {
					t.Fatalf("parseEnvBytes()[%q] = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

func TestLoadDotEnv_FromFile(t *testing.T) {
	path := writeTestEnv(t, "CONTROL_LOAD_TEST_HELLO=world\n")
	os.Unsetenv("CONTROL_LOAD_TEST_HELLO")

	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("CONTROL_LOAD_TEST_HELLO"); v != "world" {
		t.Errorf("got %q, want world", v)
	}
}

func TestLoadDotEnv_DoesNotOverride(t *testing.T) {
	os.Setenv("CONTROL_NO_OVERRIDE", "original")
	defer os.Unsetenv("CONTROL_NO_OVERRIDE")

	path := writeTestEnv(t, "CONTROL_NO_OVERRIDE=from_env_file\n")
	if err := LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("CONTROL_NO_OVERRIDE"); v != "original" {
		t.Errorf("got %q, want 'original' (should not override)", v)
	}
}

func TestLoadReadsDotEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, ".env"),
		[]byte("CONTROL_ADDRESS=127.0.0.1:19020\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	const name = "CONTROL_ADDRESS"
	previous, existed := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(name, previous)
			return
		}
		_ = os.Unsetenv(name)
	})

	if got := Load().Address; got != "127.0.0.1:19020" {
		t.Fatalf("Load().Address = %q", got)
	}
}
