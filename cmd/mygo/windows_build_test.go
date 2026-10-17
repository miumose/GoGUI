package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Even an installed NSIS must not turn a portable build into an installer.
func TestWindowsPortableBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles programs")
	}
	bin := t.TempDir()
	tool := "makensis"
	if runtime.GOOS == "windows" {
		tool += ".exe"
	}
	// Deliberately invalid: invoking it fails the build instead of producing
	// an installer, and the test never needs or downloads a real NSIS.
	if err := os.WriteFile(filepath.Join(bin, tool), []byte("NSIS must not run"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := testModule(t, map[string]string{
		"main.go":              "package main\n\nfunc main() {}\n",
		"mygo.json":            `{"name":"Portable App","identifier":"com.example.portable","version":"2.0.0","windows":{"signCommand":"echo %1>>signed.txt"}}`,
		"resources/data/a.txt": "resource",
		"resources/icon.png":   string(defaultIcon()),
	})
	c, err := loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	opts := buildOptions{sign: "-", work: t.TempDir()}
	if opts.pkg, err = packageDir(c); err != nil {
		t.Fatal(err)
	}
	artifacts, err := buildPlatform(c, "windows", "amd64", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || filepath.Base(artifacts[0]) != "Portable App.exe" {
		t.Fatalf("portable artifacts = %q", artifacts)
	}
	out := filepath.Dir(artifacts[0])
	if names, err := entryNames(out); err != nil || !slices.Equal(names, []string{"Portable App.exe", "data", "icon.png"}) {
		t.Fatalf("output = %q, %v", names, err)
	}
	if b, err := os.ReadFile(filepath.Join(out, "data", "a.txt")); err != nil || string(b) != "resource" {
		t.Fatalf("resource = %q, %v", b, err)
	}
	if image, _ := peImage(artifacts[0]); !image {
		t.Fatal("output is not a Windows executable")
	}
	// Signing remains available for the application; no installer or
	// uninstaller should be sent to the signing command.
	b, err := os.ReadFile(filepath.Join(dir, "signed.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 || filepath.Base(strings.Trim(lines[0], "\r \"")) != "Portable App.exe" {
		t.Fatalf("signed %q", lines)
	}
}

// TestWindowsSigning signs a build with a throwaway self-signed
// certificate. It runs on CI only (MYGO_TEST_SIGN), as it adds the
// certificate to the user's store for a moment.
func TestWindowsSigning(t *testing.T) {
	if runtime.GOOS != "windows" || os.Getenv("MYGO_TEST_SIGN") == "" {
		t.Skip("set MYGO_TEST_SIGN on a disposable Windows machine")
	}
	pfx := filepath.Join(t.TempDir(), "test.pfx")
	ps := func(script string) string {
		t.Helper()
		out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
		if err != nil {
			t.Fatalf("powershell: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	ps(`$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=MyGo Test" -CertStoreLocation Cert:\CurrentUser\My; ` +
		`$p = ConvertTo-SecureString -String "secret" -Force -AsPlainText; ` +
		`Export-PfxCertificate -Cert $c -FilePath "` + pfx + `" -Password $p | Out-Null; Remove-Item $c.PSPath`)
	t.Setenv("MYGO_WINDOWS_CERTIFICATE_PASSWORD", "secret")
	dir := testModule(t, map[string]string{
		"main.go":   "package main\n\nfunc main() {}\n",
		"mygo.json": `{"name": "Signed App", "version": "1.0.0", "windows": {"certificate": "` + filepath.ToSlash(pfx) + `"}}`,
	})
	c, err := loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	opts := buildOptions{sign: "-", work: t.TempDir()}
	if opts.pkg, err = packageDir(c); err != nil {
		t.Fatal(err)
	}
	artifacts, err := buildPlatform(c, "windows", "amd64", opts)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(file string) string {
		return ps(`(Get-AuthenticodeSignature "` + file + `").SignerCertificate.Subject`)
	}
	for _, a := range artifacts {
		if strings.HasSuffix(a, ".exe") {
			if subject := signer(a); subject != "CN=MyGo Test" {
				t.Errorf("%s is signed by %q", filepath.Base(a), subject)
			}
		}
	}
}
