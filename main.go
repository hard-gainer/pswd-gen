package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/huh"
	"gopkg.in/yaml.v2"
)

const (
	Letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Numbers = "0123456789"
	Symbols = "!@#$%^&*()[]{}?"

	passwordLength = 12
)

type Config map[string][]Domain

type Domain struct {
	Email    string `yaml:"email"`
	Password string `yaml:"password"`
}

func main() {

	// "c" - create flag to create an account in specific domain
	// "f" - find flag to find all accounts on specific domain
	// "u" - update flag to update an existing domain name or email
	// "d" - delete flag to delete an existing account from domain or to
	// delete an entire domain block
	var (
		createFlag = flag.Bool("c", false, "creates a new account")
		findFlag   = flag.String("f", "", "finds a specific domain")
		// updateFlag = flag.Bool("u", false, "updates a specific account in domain")
		deleteFlag = flag.String("d", "", 
			"deletes a specific account in domain" +
			"or a full domain if all accounts are selected")
	)

	flag.Parse()

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
	}()

	switch {
	case *createFlag:
		if err := handleCreateRequest(); err != nil {
			fmt.Println("Error:", err)
		}
	case *findFlag != "":
		if err := handleFindRequest(*findFlag); err != nil {
			fmt.Println("Error:", err)
		}
	// case *updateFlag != nil:
	// 	if err := handleUpdateRequest(); err != nil {
	// 		fmt.Println("Error:", err)
	// 	}
	case *deleteFlag != "":
		if err := handleDeleteRequest(*deleteFlag); err != nil {
			fmt.Println("Error:", err)
		}
	}
}

func handleCreateRequest() error {
	var inputDomainName, inputEmail string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Write a domain name:").
				Value(&inputDomainName).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("error: invalid domain name input")
					}
					return nil
				}),
		),

		huh.NewGroup(
			huh.NewInput().
				Title("Write an email:").
				Value(&inputEmail).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("error: invalid email input")
					}
					return nil
				}),
		),
	)

	err := form.Run()
	if err != nil {
		return fmt.Errorf("error running form: %w", err)
	}

	var cfg Config
	if err := loadConfigFromYaml(&cfg); err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	if cfg == nil {
		cfg = make(map[string][]Domain, 0)
	}

	newPassword, err := generatePassword(passwordLength)
	if err != nil {
		return fmt.Errorf("error generating password: %w", err)
	}

	domains := make([]Domain, 0)
	if _, isPresent := cfg[inputDomainName]; isPresent {
		domains = cfg[inputDomainName]
	}

	newDomain := Domain{
		Email:    inputEmail,
		Password: newPassword,
	}
	domains = append(domains, newDomain)
	cfg[inputDomainName] = domains

	if err := saveConfigToYaml(&cfg); err != nil {
		return fmt.Errorf("error saving config: %w", err)
	}

	fmt.Printf("Added new domain: %+v\n", newDomain)
	return nil
}

func handleFindRequest(domain string) error {
	var cfg Config

	if err := loadConfigFromYaml(&cfg); err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	if val, isPresent := cfg[domain]; isPresent {
		fmt.Println(val)
	} else {
		fmt.Printf("Domain %s not found\n", domain)
	}

	return nil
}

func handleDeleteRequest(domain string) error {
	var cfg Config

	if err := loadConfigFromYaml(&cfg); err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	domains, isPresent := cfg[domain]
	if !isPresent {
		fmt.Printf("Domain %s not found\n", domain)
	}

	var selected []Domain

	options := make([]huh.Option[Domain], len(domains))
	for i, d := range domains {
		options[i] = huh.NewOption(d.Email, d)
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[Domain]().
				Title("Selecte accounts to delete:").
				Options(options...).
				Value(&selected),
		),
	)

	if err := form.Run(); err != nil {
		return fmt.Errorf("error running form: %w", err)
	}

	remaining := make([]Domain, 0)
	for _, d := range domains {
		isSelected := false
		for _, s := range selected {
			if d.Email == s.Email {
				isSelected = true
				break
			}
		}
		if !isSelected {
			remaining = append(remaining, d)
		}
	}

	if len(remaining) == 0 {
		delete(cfg, domain)
	} else {
		cfg[domain] = remaining
	}

	if err := saveConfigToYaml(&cfg); err != nil {
		return fmt.Errorf("error saving config: %w", err)
	}

	fmt.Printf("Successfully deleted selected accounts from %s\n", domain)
	return nil
}

func generatePassword(length int) (string, error) {
	chars := Letters + Numbers + Symbols
	password := make([]byte, length)

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		password[i] = chars[n.Int64()]
	}
	return string(password), nil
}

func loadConfigFromYaml(cfg *Config) error {
	data, err := os.ReadFile("passwords.yaml")
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &cfg)
}

func saveConfigToYaml(cfg *Config) error {
	updatedData, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}

	return os.WriteFile("passwords.yaml", updatedData, 0644)
}
