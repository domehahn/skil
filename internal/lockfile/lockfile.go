package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type File struct {
	Version int     `json:"version" yaml:"version"`
	Skills  []Entry `json:"skills" yaml:"skills"`
}

type Entry struct {
	Name          string `json:"name" yaml:"name"`
	Version       string `json:"version" yaml:"version"`
	Source        string `json:"source" yaml:"source"`
	Registry      string `json:"registry,omitempty" yaml:"registry,omitempty"`
	PackageSHA256 string `json:"package_sha256" yaml:"package_sha256"`
	ContentSHA256 string `json:"content_manifest_sha256" yaml:"content_manifest_sha256"`
	SourceCommit  string `json:"source_commit,omitempty" yaml:"source_commit,omitempty"`
	Signature     string `json:"signature" yaml:"signature"`
	Provenance    string `json:"provenance" yaml:"provenance"`
}

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return File{Version: 1, Skills: []Entry{}}, nil
	}
	if err != nil {
		return File{}, err
	}
	var lock File
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&lock); err != nil {
		return lock, err
	}
	if lock.Version != 1 {
		return lock, fmt.Errorf("unsupported lockfile version %d", lock.Version)
	}
	for _, entry := range lock.Skills {
		if entry.Name == "" || entry.Version == "" || entry.Source == "" ||
			!sha256Pattern.MatchString(entry.PackageSHA256) || !sha256Pattern.MatchString(entry.ContentSHA256) ||
			entry.Signature == "" || entry.Provenance == "" {
			return lock, errors.New("lockfile contains an incomplete skill entry")
		}
	}
	return lock, nil
}

func Put(lock File, entry Entry) File {
	replaced := false
	for index := range lock.Skills {
		if lock.Skills[index].Name == entry.Name {
			lock.Skills[index] = entry
			replaced = true
		}
	}
	if !replaced {
		lock.Skills = append(lock.Skills, entry)
	}
	sort.Slice(lock.Skills, func(i, j int) bool { return lock.Skills[i].Name < lock.Skills[j].Name })
	return lock
}

func Write(path string, lock File) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(parent, ".agent-skills-lock-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return err
	}
	encoder := yaml.NewEncoder(temp)
	encoder.SetIndent(2)
	if err := encoder.Encode(lock); err != nil {
		_ = temp.Close()
		return err
	}
	if err := encoder.Close(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func Verify(lock File, name, version, source, packageDigest, contentDigest string) error {
	for _, entry := range lock.Skills {
		if entry.Name != name {
			continue
		}
		if entry.Version != version || entry.Source != source || entry.PackageSHA256 != packageDigest ||
			entry.ContentSHA256 != contentDigest {
			return fmt.Errorf("locked skill %s does not match version/source/package/content digest", name)
		}
		return nil
	}
	return fmt.Errorf("skill %s is not present in lockfile", name)
}
