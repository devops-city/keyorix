package config

import (
	"fmt"
)

type LocaleConfig struct {
	Language         string `yaml:"language"`
	FallbackLanguage string `yaml:"fallback_language"`
}

// LocaleSettings returns the configured language and fallback language. It
// satisfies i18n.LocaleSource, so i18n.Initialize(cfg) works without the i18n
// package importing this one.
func (c *Config) LocaleSettings() (language, fallbackLanguage string) {
	return c.Locale.Language, c.Locale.FallbackLanguage
}

// validateLocaleSection defaults locale.language / fallback_language to "en" and checks both are
// supported (Validate step; it writes the defaults into c).
func validateLocaleSection(c *Config) error {
	if c.Locale.Language == "" {
		c.Locale.Language = "en"
	}
	if c.Locale.FallbackLanguage == "" {
		c.Locale.FallbackLanguage = "en"
	}

	supportedLanguages := map[string]bool{
		"en": true, "ru": true, "es": true, "fr": true, "de": true,
	}
	if !supportedLanguages[c.Locale.Language] {
		return fmt.Errorf("unsupported language: %s. Supported languages: en, ru, es, fr, de", c.Locale.Language)
	}
	if !supportedLanguages[c.Locale.FallbackLanguage] {
		return fmt.Errorf("unsupported fallback language: %s. Supported languages: en, ru, es, fr, de", c.Locale.FallbackLanguage)
	}
	return nil
}
