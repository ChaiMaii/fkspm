package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func mockResponse(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}

func makeTarGz(t *testing.T, files map[string]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func TestFullWorkflowEndToEnd(t *testing.T) {
	// Build two real tarballs: http@1.0.0 -> depends on textutil@0.5.0, and http@1.1.0
	textTar, textSha := makeTarGz(t, map[string]string{
		"textutil-0.5.0/lib.fks": "note textutil library\n",
	})
	http100Tar, http100Sha := makeTarGz(t, map[string]string{
		"http-1.0.0/http.fks": "note http v1 0 0\n",
	})
	http110Tar, http110Sha := makeTarGz(t, map[string]string{
		"http-1.1.0/http.fks": "note http v1 1 0\n",
	})

	const baseURL = "https://mock.fkspm"
	idxBytes, _ := json.Marshal(RegistryIndex{
		Version: 1,
		Packages: []PackageMeta{
			{
				Name:        "http",
				Description: "Zero-symbol HTTP client and server",
				Author:      "ChaiMaii",
				License:     "WTFPL",
				Tags:        []string{"web", "net"},
				Latest:      "1.1.0",
				Versions: map[string]PackageRelease{
					"1.0.0": {
						Tarball:      baseURL + "/http-1.0.0.tar.gz",
						SHA256:       http100Sha,
						Dependencies: map[string]string{"textutil": "0.5.0"},
					},
					"1.1.0": {
						Tarball:      baseURL + "/http-1.1.0.tar.gz",
						SHA256:       http110Sha,
						Dependencies: map[string]string{"textutil": "0.5.0"},
					},
				},
			},
			{
				Name:        "textutil",
				Description: "Text helper functions",
				Author:      "ChaiMaii",
				License:     "WTFPL",
				Latest:      "0.5.0",
				Versions: map[string]PackageRelease{
					"0.5.0": {
						Tarball: baseURL + "/textutil-0.5.0.tar.gz",
						SHA256:  textSha,
					},
				},
			},
		},
	})

	httpClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/index.json":
				return mockResponse(http.StatusOK, idxBytes), nil
			case "/http-1.0.0.tar.gz":
				return mockResponse(http.StatusOK, http100Tar), nil
			case "/http-1.1.0.tar.gz":
				return mockResponse(http.StatusOK, http110Tar), nil
			case "/textutil-0.5.0.tar.gz":
				return mockResponse(http.StatusOK, textTar), nil
			default:
				return mockResponse(http.StatusNotFound, nil), nil
			}
		}),
	}

	workDir := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	var out, errOut bytes.Buffer
	client := &Client{
		IndexURL: baseURL + "/index.json",
		CacheDir: cacheDir,
		HTTP:     httpClient,
		Out:      &out,
		ErrOut:   &errOut,
	}

	// 1. init
	if err := client.run(workDir, []string{"init"}); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, manifestFile)); err != nil {
		t.Fatalf("manifest.fks not created: %v", err)
	}

	// 2. search
	out.Reset()
	if err := client.run(workDir, []string{"search", "web"}); err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if !strings.Contains(out.String(), "http") {
		t.Fatalf("search output missing http: %s", out.String())
	}

	// 3. add http 1.0.0 (should also pull transitive dep textutil@0.5.0)
	out.Reset()
	if err := client.run(workDir, []string{"add", "http", "1.0.0"}); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	httpContent, err := os.ReadFile(filepath.Join(workDir, modulesDir, "http", "http.fks"))
	if err != nil || !strings.Contains(string(httpContent), "v1 0 0") {
		t.Fatalf("http@1.0.0 not extracted properly: err=%v content=%q", err, string(httpContent))
	}
	if _, err := os.Stat(filepath.Join(workDir, modulesDir, "textutil", "lib.fks")); err != nil {
		t.Fatalf("transitive dep textutil not extracted: %v", err)
	}

	// 4. update http -> 1.1.0
	out.Reset()
	if err := client.run(workDir, []string{"update", "http"}); err != nil {
		t.Fatalf("update failed: %v", err)
	}
	httpContent, _ = os.ReadFile(filepath.Join(workDir, modulesDir, "http", "http.fks"))
	if !strings.Contains(string(httpContent), "v1 1 0") {
		t.Fatalf("expected http@1.1.0 after update, got %q", string(httpContent))
	}

	// 5. list
	out.Reset()
	if err := client.run(workDir, []string{"list"}); err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if !strings.Contains(out.String(), "http") || !strings.Contains(out.String(), "[installed]") {
		t.Fatalf("unexpected list output: %s", out.String())
	}

	// 6. wipe fkspm_modules and re-install from manifest.fks + lock.fks
	_ = os.RemoveAll(filepath.Join(workDir, modulesDir))
	if err := client.run(workDir, []string{"install"}); err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, modulesDir, "http", "http.fks")); err != nil {
		t.Fatalf("install did not restore http: %v", err)
	}

	// 7. remove http
	if err := client.run(workDir, []string{"remove", "http"}); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, modulesDir, "http")); !os.IsNotExist(err) {
		t.Fatalf("http directory still exists after remove")
	}
}

func TestChecksumMismatchRejected(t *testing.T) {
	badTar, _ := makeTarGz(t, map[string]string{"pkg/a.fks": "note tampered\n"})
	const baseURL = "https://mock.fkspm"
	idxBytes, _ := json.Marshal(RegistryIndex{
		Version: 1,
		Packages: []PackageMeta{{
			Name:   "evil",
			Latest: "1.0.0",
			Versions: map[string]PackageRelease{
				"1.0.0": {
					Tarball: baseURL + "/evil.tar.gz",
					SHA256:  "0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		}},
	})
	httpClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/index.json" {
				return mockResponse(http.StatusOK, idxBytes), nil
			}
			return mockResponse(http.StatusOK, badTar), nil
		}),
	}

	workDir := t.TempDir()
	client := &Client{
		IndexURL: baseURL + "/index.json",
		CacheDir: filepath.Join(t.TempDir(), "cache"),
		HTTP:     httpClient,
		Out:      &bytes.Buffer{},
		ErrOut:   &bytes.Buffer{},
	}
	_ = client.run(workDir, []string{"init"})
	err := client.run(workDir, []string{"add", "evil"})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error, got: %v", err)
	}
}
