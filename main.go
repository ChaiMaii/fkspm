package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	fkspmVersion    = "0.1.0"
	defaultIndexURL = "https://chaimaii.github.io/fkspm-index/index.json"
	manifestFile    = "manifest.fks"
	lockFile        = "lock.fks"
	modulesDir      = "fkspm_modules"
)

// ============================================================================
// 1. REGISTRY INDEX SCHEMA
// ============================================================================

type RegistryIndex struct {
	Version   int           `json:"version"`
	UpdatedAt string        `json:"updated_at"`
	Packages  []PackageMeta `json:"packages"`
}

type PackageMeta struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Author      string                    `json:"author"`
	License     string                    `json:"license"`
	Repository  string                    `json:"repository"`
	Tags        []string                  `json:"tags"`
	Latest      string                    `json:"latest"`
	Versions    map[string]PackageRelease `json:"versions"`
}

type PackageRelease struct {
	Tarball      string            `json:"tarball"`
	SHA256       string            `json:"sha256"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
}

func (idx *RegistryIndex) Find(name string) (*PackageMeta, bool) {
	for i := range idx.Packages {
		if idx.Packages[i].Name == name {
			return &idx.Packages[i], true
		}
	}
	return nil, false
}

// ============================================================================
// 2. ZERO-SYMBOL MANIFEST (manifest.fks) & LOCKFILE (lock.fks)
// ============================================================================

type Manifest struct {
	Name        string
	Version     string // semver string e.g. "0.1.0" (serialized as "0 1 0")
	Author      string
	License     string
	Description string
	Requires    map[string]string // pkg -> version ("1.2.0" or "latest")
}

type LockEntry struct {
	Name    string
	Version string
	SHA256  string
}

type Lockfile struct {
	Entries map[string]LockEntry
}

func formatFksVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || v == "latest" {
		return "latest"
	}
	return strings.ReplaceAll(v, ".", " ")
}

func parseFksVersion(words []string) string {
	if len(words) == 0 {
		return "latest"
	}
	if len(words) == 1 && words[0] == "latest" {
		return "latest"
	}
	return strings.Join(words, ".")
}

func readManifest(dir string) (*Manifest, error) {
	path := filepath.Join(dir, manifestFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := &Manifest{
		Version:  "0.1.0",
		License:  "WTFPL",
		Requires: map[string]string{},
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || line == "note" || strings.HasPrefix(line, "note ") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "package":
			if len(fields) >= 2 {
				m.Name = fields[1]
			}
			if len(fields) >= 4 && fields[2] == "version" {
				m.Version = parseFksVersion(fields[3:])
			}
		case "author":
			if len(fields) >= 2 {
				m.Author = strings.Join(fields[1:], " ")
			}
		case "license":
			if len(fields) >= 2 {
				m.License = strings.Join(fields[1:], " ")
			}
		case "description":
			rest := strings.TrimSpace(strings.TrimPrefix(line, "description"))
			if strings.HasPrefix(rest, "say ") && strings.HasSuffix(rest, " end") && len(rest) >= 8 {
				m.Description = rest[4 : len(rest)-4]
			} else {
				m.Description = rest
			}
		case "require":
			if len(fields) >= 2 {
				pkg := fields[1]
				ver := "latest"
				if len(fields) >= 4 && fields[2] == "version" {
					ver = parseFksVersion(fields[3:])
				}
				m.Requires[pkg] = ver
			}
		}
	}
	if m.Name == "" {
		return nil, errors.New("manifest.fks is missing a 'package <name> version <maj> <min> <patch>' declaration")
	}
	return m, nil
}

func writeManifest(dir string, m *Manifest) error {
	var b strings.Builder
	b.WriteString("note FakeScript project manifest\n\n")
	b.WriteString(fmt.Sprintf("package %s version %s\n", m.Name, formatFksVersion(m.Version)))
	if m.Author != "" {
		b.WriteString(fmt.Sprintf("author %s\n", m.Author))
	}
	if m.License != "" {
		b.WriteString(fmt.Sprintf("license %s\n", m.License))
	}
	if m.Description != "" {
		b.WriteString(fmt.Sprintf("description say %s end\n", m.Description))
	}
	if len(m.Requires) > 0 {
		b.WriteString("\n")
		var names []string
		for k := range m.Requires {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			ver := m.Requires[name]
			if ver == "" || ver == "latest" {
				b.WriteString(fmt.Sprintf("require %s\n", name))
			} else {
				b.WriteString(fmt.Sprintf("require %s version %s\n", name, formatFksVersion(ver)))
			}
		}
	}
	return os.WriteFile(filepath.Join(dir, manifestFile), []byte(b.String()), 0644)
}

func readLockfile(dir string) *Lockfile {
	lf := &Lockfile{Entries: map[string]LockEntry{}}
	data, err := os.ReadFile(filepath.Join(dir, lockFile))
	if err != nil {
		return lf
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || line == "note" || strings.HasPrefix(line, "note ") {
			continue
		}
		f := strings.Fields(line)
		// locked <name> version <maj> <min> <patch> sha <hex>
		if len(f) >= 6 && f[0] == "locked" && f[2] == "version" {
			shaIdx := -1
			for i := 3; i < len(f); i++ {
				if f[i] == "sha" {
					shaIdx = i
					break
				}
			}
			if shaIdx > 3 && shaIdx+1 < len(f) {
				lf.Entries[f[1]] = LockEntry{
					Name:    f[1],
					Version: parseFksVersion(f[3:shaIdx]),
					SHA256:  f[shaIdx+1],
				}
			}
		}
	}
	return lf
}

func writeLockfile(dir string, lf *Lockfile) error {
	var b strings.Builder
	b.WriteString("note fkspm lockfile generated automatically\n\n")
	var names []string
	for k := range lf.Entries {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		e := lf.Entries[name]
		b.WriteString(fmt.Sprintf("locked %s version %s sha %s\n", e.Name, formatFksVersion(e.Version), e.SHA256))
	}
	return os.WriteFile(filepath.Join(dir, lockFile), []byte(b.String()), 0644)
}

// ============================================================================
// 3. REGISTRY CLIENT, CACHE & TARBALL EXTRACTION
// ============================================================================

type Client struct {
	IndexURL string
	CacheDir string
	HTTP     *http.Client
	Out      io.Writer
	ErrOut   io.Writer
}

func newDefaultClient() *Client {
	indexURL := os.Getenv("FKSPM_INDEX_URL")
	if indexURL == "" {
		indexURL = defaultIndexURL
	}
	cacheDir := os.Getenv("FKSPM_CACHE_DIR")
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, ".fkspm", "cache")
	}
	return &Client{
		IndexURL: indexURL,
		CacheDir: cacheDir,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Out:      os.Stdout,
		ErrOut:   os.Stderr,
	}
}

func (c *Client) fetchIndex() (*RegistryIndex, error) {
	var data []byte
	var err error
	if strings.HasPrefix(c.IndexURL, "http://") || strings.HasPrefix(c.IndexURL, "https://") {
		resp, reqErr := c.HTTP.Get(c.IndexURL)
		if reqErr != nil {
			return nil, fmt.Errorf("failed to fetch registry index (%s): %w", c.IndexURL, reqErr)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("registry index returned HTTP %d (%s)", resp.StatusCode, c.IndexURL)
		}
		data, err = io.ReadAll(resp.Body)
	} else {
		path := strings.TrimPrefix(c.IndexURL, "file://")
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read registry index: %w", err)
	}
	var idx RegistryIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("invalid registry index JSON: %w", err)
	}
	return &idx, nil
}

func (c *Client) downloadVerifiedTarball(pkgName, version string, rel PackageRelease) (string, error) {
	pkgCacheDir := filepath.Join(c.CacheDir, pkgName)
	if err := os.MkdirAll(pkgCacheDir, 0755); err != nil {
		return "", err
	}
	tarPath := filepath.Join(pkgCacheDir, version+".tar.gz")

	// Check existing cache
	if _, err := os.Stat(tarPath); err == nil {
		if rel.SHA256 == "" || verifyFileSHA256(tarPath, rel.SHA256) == nil {
			return tarPath, nil
		}
		_ = os.Remove(tarPath)
	}

	var body []byte
	var err error
	if strings.HasPrefix(rel.Tarball, "http://") || strings.HasPrefix(rel.Tarball, "https://") {
		resp, reqErr := c.HTTP.Get(rel.Tarball)
		if reqErr != nil {
			return "", fmt.Errorf("download %s@%s failed: %w", pkgName, version, reqErr)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("download %s@%s returned HTTP %d", pkgName, version, resp.StatusCode)
		}
		body, err = io.ReadAll(resp.Body)
	} else {
		body, err = os.ReadFile(strings.TrimPrefix(rel.Tarball, "file://"))
	}
	if err != nil {
		return "", fmt.Errorf("read %s@%s tarball failed: %w", pkgName, version, err)
	}

	sum := sha256.Sum256(body)
	gotHex := hex.EncodeToString(sum[:])
	if rel.SHA256 != "" && !strings.EqualFold(gotHex, rel.SHA256) {
		return "", fmt.Errorf("checksum mismatch for %s@%s: expected %s, got %s", pkgName, version, rel.SHA256, gotHex)
	}

	if err := os.WriteFile(tarPath, body, 0644); err != nil {
		return "", err
	}
	return tarPath, nil
}

func verifyFileSHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expected, got)
	}
	return nil
}

func extractTarGz(tarPath, destDir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("invalid gzip archive: %w", err)
	}
	defer gz.Close()

	// Clean destination first
	if err := os.RemoveAll(destDir); err != nil {
		return err
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	// Read entries into memory first to detect a common single top-level directory (GitHub release tarballs)
	type entry struct {
		name string
		dir  bool
		data []byte
	}
	var entries []entry
	tr := tar.NewReader(gz)
	topDirs := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid tar archive: %w", err)
		}
		clean := filepath.ToSlash(filepath.Clean(hdr.Name))
		if clean == "." || clean == "" || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "..") {
			continue
		}
		parts := strings.Split(clean, "/")
		topDirs[parts[0]] = true

		switch hdr.Typeflag {
		case tar.TypeDir:
			entries = append(entries, entry{name: clean, dir: true})
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			entries = append(entries, entry{name: clean, data: b})
		}
	}

	stripTop := len(topDirs) == 1
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}

	for _, e := range entries {
		rel := e.name
		if stripTop {
			parts := strings.SplitN(rel, "/", 2)
			if len(parts) < 2 || parts[1] == "" {
				continue
			}
			rel = parts[1]
		}
		target := filepath.Join(absDest, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, absDest+string(os.PathSeparator)) && target != absDest {
			return fmt.Errorf("illegal path in archive: %s", e.name)
		}
		if e.dir {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(target, e.data, 0644); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// 4. DEPENDENCY RESOLUTION & COMMANDS
// ============================================================================

func (c *Client) resolveAndInstall(workDir string, idx *RegistryIndex, targets map[string]string, lf *Lockfile) error {
	visited := map[string]string{}
	var queue []string
	for name := range targets {
		queue = append(queue, name)
	}
	sort.Strings(queue)

	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]

		if _, done := visited[name]; done {
			continue
		}

		meta, ok := idx.Find(name)
		if !ok {
			return fmt.Errorf("package %q not found in registry", name)
		}

		wantVer := targets[name]
		if wantVer == "" || wantVer == "latest" {
			wantVer = meta.Latest
		}
		rel, ok := meta.Versions[wantVer]
		if !ok {
			return fmt.Errorf("package %q has no version %q (latest is %s)", name, wantVer, meta.Latest)
		}

		visited[name] = wantVer
		tarPath, err := c.downloadVerifiedTarball(name, wantVer, rel)
		if err != nil {
			return err
		}

		dest := filepath.Join(workDir, modulesDir, name)
		if err := extractTarGz(tarPath, dest); err != nil {
			return fmt.Errorf("extract %s@%s: %w", name, wantVer, err)
		}

		sha := rel.SHA256
		if sha == "" {
			if b, err := os.ReadFile(tarPath); err == nil {
				s := sha256.Sum256(b)
				sha = hex.EncodeToString(s[:])
			}
		}
		lf.Entries[name] = LockEntry{Name: name, Version: wantVer, SHA256: sha}
		fmt.Fprintf(c.Out, "  + %s@%s\n", name, wantVer)

		// Enqueue transitive dependencies
		for depName, depVer := range rel.Dependencies {
			if _, seen := visited[depName]; !seen {
				if _, exists := targets[depName]; !exists {
					targets[depName] = depVer
				}
				queue = append(queue, depName)
			}
		}
	}
	return nil
}

func (c *Client) cmdInit(workDir string, args []string) error {
	targetDir := workDir
	name := filepath.Base(workDir)
	if len(args) > 0 {
		name = sanitizeIdent(args[0])
		targetDir = filepath.Join(workDir, name)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return err
		}
	} else {
		name = sanitizeIdent(name)
	}

	if _, err := os.Stat(filepath.Join(targetDir, manifestFile)); err == nil {
		return fmt.Errorf("%s already exists in %s", manifestFile, targetDir)
	}

	m := &Manifest{
		Name:        name,
		Version:     "0.1.0",
		License:     "WTFPL",
		Description: "A FakeScript project",
		Requires:    map[string]string{},
	}
	if err := writeManifest(targetDir, m); err != nil {
		return err
	}

	mainFks := filepath.Join(targetDir, "main.fks")
	if _, err := os.Stat(mainFks); os.IsNotExist(err) {
		starter := "note " + name + " entry point\n\nimport print\n\nfn main do\n    ln of print contains say hello from " + name + " end\nend\n\nexec main\n"
		if err := os.WriteFile(mainFks, []byte(starter), 0644); err != nil {
			return err
		}
	}

	gitignore := filepath.Join(targetDir, ".gitignore")
	if _, err := os.Stat(gitignore); os.IsNotExist(err) {
		_ = os.WriteFile(gitignore, []byte("fkspm_modules/\n*.exe\n"), 0644)
	}

	fmt.Fprintf(c.Out, "Initialized FakeScript project %q in %s\n", name, targetDir)
	fmt.Fprintf(c.Out, "  created %s\n  created main.fks\n", manifestFile)
	return nil
}

func sanitizeIdent(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "myapp"
	}
	return strings.ToLower(b.String())
}

func (c *Client) cmdSearch(args []string) error {
	query := ""
	if len(args) > 0 {
		query = strings.ToLower(strings.Join(args, " "))
	}
	idx, err := c.fetchIndex()
	if err != nil {
		return err
	}
	found := 0
	for _, p := range idx.Packages {
		match := query == "" ||
			strings.Contains(strings.ToLower(p.Name), query) ||
			strings.Contains(strings.ToLower(p.Description), query) ||
			strings.Contains(strings.ToLower(p.Author), query)
		if !match {
			for _, t := range p.Tags {
				if strings.Contains(strings.ToLower(t), query) {
					match = true
					break
				}
			}
		}
		if match {
			fmt.Fprintf(c.Out, "%-16s v%-8s %s\n", p.Name, p.Latest, p.Description)
			found++
		}
	}
	if found == 0 {
		fmt.Fprintf(c.Out, "No packages found matching %q\n", query)
	}
	return nil
}

func (c *Client) cmdInfo(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: fkspm info <package>")
	}
	idx, err := c.fetchIndex()
	if err != nil {
		return err
	}
	p, ok := idx.Find(args[0])
	if !ok {
		return fmt.Errorf("package %q not found", args[0])
	}
	fmt.Fprintf(c.Out, "%s (v%s)\n", p.Name, p.Latest)
	fmt.Fprintf(c.Out, "  Description: %s\n", p.Description)
	fmt.Fprintf(c.Out, "  Author:      %s\n", p.Author)
	fmt.Fprintf(c.Out, "  License:     %s\n", p.License)
	if p.Repository != "" {
		fmt.Fprintf(c.Out, "  Repository:  %s\n", p.Repository)
	}
	if len(p.Tags) > 0 {
		fmt.Fprintf(c.Out, "  Tags:        %s\n", strings.Join(p.Tags, ", "))
	}
	var vers []string
	for v := range p.Versions {
		vers = append(vers, v)
	}
	sort.Strings(vers)
	fmt.Fprintf(c.Out, "  Versions:    %s\n", strings.Join(vers, ", "))
	return nil
}

func (c *Client) cmdAdd(workDir string, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: fkspm add <package> [version]")
	}
	m, err := readManifest(workDir)
	if err != nil {
		return fmt.Errorf("cannot read %s (run 'fkspm init' first): %w", manifestFile, err)
	}
	idx, err := c.fetchIndex()
	if err != nil {
		return err
	}

	pkgName := args[0]
	wantVer := "latest"
	if len(args) >= 2 {
		wantVer = strings.TrimPrefix(strings.Join(args[1:], "."), "v")
	}
	meta, ok := idx.Find(pkgName)
	if !ok {
		return fmt.Errorf("package %q not found in registry", pkgName)
	}
	if wantVer == "latest" {
		wantVer = meta.Latest
	}
	if _, ok := meta.Versions[wantVer]; !ok {
		return fmt.Errorf("package %q has no version %q", pkgName, wantVer)
	}

	m.Requires[pkgName] = wantVer
	lf := readLockfile(workDir)
	targets := map[string]string{pkgName: wantVer}
	if err := c.resolveAndInstall(workDir, idx, targets, lf); err != nil {
		return err
	}
	if err := writeManifest(workDir, m); err != nil {
		return err
	}
	if err := writeLockfile(workDir, lf); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Added %s@%s\n", pkgName, wantVer)
	return nil
}

func (c *Client) cmdRemove(workDir string, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: fkspm remove <package>")
	}
	m, err := readManifest(workDir)
	if err != nil {
		return err
	}
	pkgName := args[0]
	if _, ok := m.Requires[pkgName]; !ok {
		return fmt.Errorf("package %q is not in %s", pkgName, manifestFile)
	}
	delete(m.Requires, pkgName)
	lf := readLockfile(workDir)
	delete(lf.Entries, pkgName)

	_ = os.RemoveAll(filepath.Join(workDir, modulesDir, pkgName))
	if err := writeManifest(workDir, m); err != nil {
		return err
	}
	if err := writeLockfile(workDir, lf); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Removed %s\n", pkgName)
	return nil
}

func (c *Client) cmdInstall(workDir string) error {
	m, err := readManifest(workDir)
	if err != nil {
		return err
	}
	if len(m.Requires) == 0 {
		fmt.Fprintln(c.Out, "No dependencies to install.")
		return nil
	}
	idx, err := c.fetchIndex()
	if err != nil {
		return err
	}
	lf := readLockfile(workDir)
	targets := map[string]string{}
	for k, v := range m.Requires {
		if locked, ok := lf.Entries[k]; ok && (v == "latest" || v == locked.Version) {
			targets[k] = locked.Version
		} else {
			targets[k] = v
		}
	}
	if err := c.resolveAndInstall(workDir, idx, targets, lf); err != nil {
		return err
	}
	if err := writeLockfile(workDir, lf); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "Installed %d package(s) into %s/\n", len(lf.Entries), modulesDir)
	return nil
}

func (c *Client) cmdUpdate(workDir string, args []string) error {
	m, err := readManifest(workDir)
	if err != nil {
		return err
	}
	idx, err := c.fetchIndex()
	if err != nil {
		return err
	}
	lf := readLockfile(workDir)

	var toUpdate []string
	if len(args) > 0 {
		if _, ok := m.Requires[args[0]]; !ok {
			return fmt.Errorf("package %q is not in %s", args[0], manifestFile)
		}
		toUpdate = []string{args[0]}
	} else {
		for k := range m.Requires {
			toUpdate = append(toUpdate, k)
		}
		sort.Strings(toUpdate)
	}

	targets := map[string]string{}
	for _, name := range toUpdate {
		meta, ok := idx.Find(name)
		if !ok {
			return fmt.Errorf("package %q not found in registry", name)
		}
		m.Requires[name] = meta.Latest
		targets[name] = meta.Latest
	}

	if err := c.resolveAndInstall(workDir, idx, targets, lf); err != nil {
		return err
	}
	if err := writeManifest(workDir, m); err != nil {
		return err
	}
	if err := writeLockfile(workDir, lf); err != nil {
		return err
	}
	fmt.Fprintln(c.Out, "Dependencies updated.")
	return nil
}

func (c *Client) cmdList(workDir string) error {
	m, err := readManifest(workDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "%s@%s\n", m.Name, m.Version)
	if len(m.Requires) == 0 {
		fmt.Fprintln(c.Out, "  (no dependencies)")
		return nil
	}
	var names []string
	for k := range m.Requires {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		status := "missing"
		if _, err := os.Stat(filepath.Join(workDir, modulesDir, name)); err == nil {
			status = "installed"
		}
		fmt.Fprintf(c.Out, "  %-16s v%-8s [%s]\n", name, m.Requires[name], status)
	}
	return nil
}

func (c *Client) cmdCache(args []string) error {
	if len(args) == 0 || args[0] == "dir" {
		fmt.Fprintln(c.Out, c.CacheDir)
		return nil
	}
	if args[0] == "clean" {
		if err := os.RemoveAll(c.CacheDir); err != nil {
			return err
		}
		fmt.Fprintf(c.Out, "Cleared cache at %s\n", c.CacheDir)
		return nil
	}
	return errors.New("usage: fkspm cache [dir|clean]")
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `fkspm v%s — FakeScript Package Manager

Usage:
  fkspm init [name]             Initialize a new FakeScript project
  fkspm search [query]          Search packages in the registry
  fkspm info <pkg>              Show package details and versions
  fkspm add <pkg> [version]     Add and install a package
  fkspm remove <pkg>            Remove a package
  fkspm install                 Install all dependencies from manifest.fks
  fkspm update [pkg]            Update one or all packages to latest
  fkspm list                    List project dependencies
  fkspm cache [dir|clean]       Inspect or clear local package cache
  fkspm version                 Print fkspm version
`, fkspmVersion)
}

func (c *Client) run(workDir string, args []string) error {
	if len(args) == 0 {
		printUsage(c.ErrOut)
		return errors.New("missing command")
	}
	switch args[0] {
	case "version", "-v", "--version":
		fmt.Fprintf(c.Out, "fkspm v%s (%s/%s)\n", fkspmVersion, runtime.GOOS, runtime.GOARCH)
		return nil
	case "help", "-h", "--help":
		printUsage(c.Out)
		return nil
	case "init":
		return c.cmdInit(workDir, args[1:])
	case "search":
		return c.cmdSearch(args[1:])
	case "info":
		return c.cmdInfo(args[1:])
	case "add":
		return c.cmdAdd(workDir, args[1:])
	case "remove", "rm":
		return c.cmdRemove(workDir, args[1:])
	case "install", "i":
		return c.cmdInstall(workDir)
	case "update":
		return c.cmdUpdate(workDir, args[1:])
	case "list", "ls":
		return c.cmdList(workDir)
	case "cache":
		return c.cmdCache(args[1:])
	default:
		return fmt.Errorf("unknown command %q (run 'fkspm help' for usage)", args[0])
	}
}

func main() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client := newDefaultClient()
	if err := client.run(wd, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
