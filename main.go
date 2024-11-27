package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

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
		fmt.Println("Error running form:", err)
	}

	var cfg Config
	readFromYaml(&cfg)

	if cfg == nil {
		cfg = make(map[string][]Domain, 0)
	}

	newPassword, err := generatePassword(passwordLength)
	if err != nil {
		fmt.Println(err)
		return
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

	serealizeIntoYaml(&cfg)

	fmt.Printf("Added new domain: %+v\n", newDomain)
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

func readFromYaml(cfg *Config) {
	data, err := os.ReadFile("passwords.yaml")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func serealizeIntoYaml(cfg *Config) {
	updatedData, err := yaml.Marshal(&cfg)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = os.WriteFile("passwords.yaml", updatedData, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
}
