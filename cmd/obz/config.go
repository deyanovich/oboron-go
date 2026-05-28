package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"oboron.org/go/oboron/ztier"
)

// Config represents the main configuration file for the obz CLI.
type Config struct {
	Profile  string `json:"profile"`
	Scheme   string `json:"scheme"`
	Encoding string `json:"encoding,omitempty"`
}

// SecretProfile represents a profile storing a 64-char hex secret.
type SecretProfile struct {
	Secret string `json:"secret"`
}

func obzDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	// obz shares the ~/.oboron/ root with ob, under the ztier/ subdir (CLI §3).
	return filepath.Join(home, ".oboron", "ztier")
}

func configPath() string {
	return filepath.Join(obzDir(), "config.json")
}

func profileDir() string {
	return filepath.Join(obzDir(), "profiles")
}

// validateProfileName checks that a profile name is a safe filename with no path separators.
func validateProfileName(name string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	for _, c := range name {
		if c == '/' || c == '\\' || c == '\x00' || c == '.' {
			return fmt.Errorf("profile name %q contains invalid character %q", name, c)
		}
	}
	return nil
}

func profilePath(name string) string {
	return filepath.Join(profileDir(), name+".json")
}

func backupDir() string {
	return filepath.Join(obzDir(), "bkp")
}

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Scheme == "" {
		cfg.Scheme = "zrbcx"
	}
	if cfg.Profile == "" {
		cfg.Profile = "default"
	}

	return &cfg, nil
}

func saveConfig(cfg *Config) error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

func loadProfile(name string) (*SecretProfile, error) {
	if err := validateProfileName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(profilePath(name))
	if err != nil {
		return nil, fmt.Errorf("failed to read secret profile %q: %w\nHint: run 'obz init' or 'obz profile create %s'", name, err, name)
	}

	var p SecretProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse secret profile %q: %w", name, err)
	}
	return &p, nil
}

func saveProfile(name string, p *SecretProfile) error {
	if err := validateProfileName(name); err != nil {
		return err
	}
	path := profilePath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	// Backup existing profile if present
	if _, err := os.Stat(path); err == nil {
		bkp := filepath.Join(backupDir(), fmt.Sprintf("%s-%s.json", name, time.Now().Format("20060102-150405")))
		if err := os.MkdirAll(filepath.Dir(bkp), 0700); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
		if data, err := os.ReadFile(path); err == nil {
			if err := os.WriteFile(bkp, data, 0600); err != nil {
				return fmt.Errorf("failed to backup profile: %w", err)
			}
			fmt.Printf("Backed up existing profile to: %s\n", bkp)
		}
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

func generateSecret() (*ztier.Secret, error) {
	raw := make([]byte, ztier.SecretSize)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return ztier.NewSecret(raw)
}

func listProfiles() error {
	entries, err := os.ReadDir(profileDir())
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No profiles found. Run 'obz init' to create one.")
			return nil
		}
		return err
	}

	cfg, _ := loadConfig()
	active := ""
	if cfg != nil {
		active = cfg.Profile
	}

	var profiles []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			profiles = append(profiles, e.Name()[:len(e.Name())-5])
		}
	}

	if len(profiles) == 0 {
		fmt.Println("No profiles found.")
		return nil
	}

	fmt.Println("Available profiles:")
	for _, name := range profiles {
		marker := ""
		if name == active {
			marker = " (active)"
		}
		fmt.Printf("  %s%s\n", name, marker)
	}
	return nil
}

func createProfile(name string, secret *ztier.Secret) error {
	p := &SecretProfile{Secret: secret.Hex()}
	if err := saveProfile(name, p); err != nil {
		return err
	}
	fmt.Printf("✓ Created profile %q\n", name)
	fmt.Printf("  Secret: %s\n", secret.Hex())
	fmt.Println("\n⚠️  Keep this secret secure!")
	return nil
}

func deleteProfile(name string) error {
	if err := validateProfileName(name); err != nil {
		return err
	}
	path := profilePath(name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("profile %q does not exist", name)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	fmt.Printf("✓ Deleted profile %q\n", name)
	return nil
}

func renameProfile(oldName, newName string) error {
	if err := validateProfileName(oldName); err != nil {
		return err
	}
	if err := validateProfileName(newName); err != nil {
		return err
	}
	oldPath := profilePath(oldName)
	newPath := profilePath(newName)

	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return fmt.Errorf("profile %q does not exist", oldName)
	}
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("profile %q already exists", newName)
	}

	if err := os.MkdirAll(filepath.Dir(newPath), 0700); err != nil {
		return err
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	fmt.Printf("✓ Renamed profile %q to %q\n", oldName, newName)
	return nil
}
