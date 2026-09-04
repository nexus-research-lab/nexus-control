package logx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollingFileWriterCreatesPrivateControlDirectory(t *testing.T) {
	controlDir := filepath.Join(t.TempDir(), "control")
	writer, err := newRollingFileWriter(FileOptions{
		Enabled: true,
		Path:    filepath.Join(controlDir, "logs", "logger.log"),
	})
	if err != nil {
		t.Fatalf("创建日志写入器失败: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	info, err := os.Stat(controlDir)
	if err != nil {
		t.Fatalf("读取 Control 目录失败: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o700 {
		t.Fatalf("Control 目录权限 = %o，期望 700", permissions)
	}
}
