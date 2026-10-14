package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

// Embed the locales directory
//
//go:embed locales/*.json
var localeEmbedFS embed.FS

// localeFS is the filesystem used to load translation files.
// It can be replaced in tests via setLocaleFSForTesting.
var localeFS fs.FS = localeEmbedFS

// Localizer provides translation functionality
type Localizer struct {
	bundle       *i18n.Bundle
	localizer    *i18n.Localizer
	currentLang  string
	fallbackLang string
	mutex        sync.RWMutex
}

// Global instance of the localizer
var globalLocalizer *Localizer
var once sync.Once
var globMu sync.RWMutex

// LocaleSource is what Initialize needs from the application config: the
// configured language and fallback language. *config.Config implements it
// (config.Config.LocaleSettings). Taking this narrow interface instead of
// *config.Config keeps this package from importing internal/config, so the
// many packages that translate messages don't link config's dependencies.
type LocaleSource interface {
	LocaleSettings() (language, fallbackLanguage string)
}

// fixedLocale is a LocaleSource with fixed values.
type fixedLocale struct{ lang, fallback string }

func (f fixedLocale) LocaleSettings() (string, string) { return f.lang, f.fallback }

// InitializeForTesting sets up the i18n system with default config for testing
func InitializeForTesting() error {
	return Initialize(fixedLocale{lang: "en", fallback: "en"})
}

// Initialize sets up the i18n system with the provided config
func Initialize(cfg LocaleSource) error {
	lang, fallback := cfg.LocaleSettings()
	var initErr error
	once.Do(func() {
		l := &Localizer{
			bundle:       i18n.NewBundle(language.English),
			currentLang:  lang,
			fallbackLang: fallback,
		}

		// If no language is specified, use English
		if l.currentLang == "" {
			l.currentLang = "en"
		}

		// If no fallback language is specified, use English
		if l.fallbackLang == "" {
			l.fallbackLang = "en"
		}

		// Configure the bundle
		l.bundle.RegisterUnmarshalFunc("json", json.Unmarshal)

		// Load all translation files
		if err := loadTranslationFiles(l.bundle); err != nil {
			initErr = fmt.Errorf("error loading translation files: %w", err)
			return
		}

		// Create the localizer with the current language and fallback
		l.localizer = i18n.NewLocalizer(
			l.bundle,
			l.currentLang,
			l.fallbackLang,
		)

		globMu.Lock()
		globalLocalizer = l
		globMu.Unlock()
	})

	return initErr
}

// loadTranslationFiles loads all translation files from the embedded filesystem
func loadTranslationFiles(bundle *i18n.Bundle) error {
	entries, err := fs.ReadDir(localeFS, "locales")
	if err != nil {
		return fmt.Errorf("failed to read locales directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join("locales", entry.Name())
		data, err := fs.ReadFile(localeFS, filePath)
		if err != nil {
			return fmt.Errorf("failed to read translation file %s: %w", filePath, err)
		}

		if _, err := bundle.ParseMessageFileBytes(data, filePath); err != nil {
			return fmt.Errorf("failed to parse translation file %s: %w", filePath, err)
		}
	}

	return nil
}

// GetLocalizer returns the global localizer instance
func GetLocalizer() *Localizer {
	globMu.RLock()
	l := globalLocalizer
	globMu.RUnlock()
	if l == nil {
		panic("i18n not initialized, call Initialize() first")
	}
	return l
}

// SetLanguage changes the current language
func (l *Localizer) SetLanguage(lang string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.currentLang = lang
	l.localizer = i18n.NewLocalizer(l.bundle, l.currentLang, l.fallbackLang)
}

// Localize translates a message ID with optional template data
func (l *Localizer) Localize(messageID string, templateData map[string]any) string {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	msg, err := l.localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    messageID,
		TemplateData: templateData,
	})

	if err != nil {
		// If translation fails, return the message ID as fallback
		return messageID
	}

	return msg
}

// MustLocalize is like Localize but panics if the message is not found
func (l *Localizer) MustLocalize(messageID string, templateData map[string]any) string {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	msg, err := l.localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    messageID,
		TemplateData: templateData,
	})

	if err != nil {
		panic(fmt.Sprintf("missing translation for message ID: %s", messageID))
	}

	return msg
}

// T is a shorthand for Localize
func T(messageID string, templateData map[string]any) string {
	return GetLocalizer().Localize(messageID, templateData)
}

// MustT is a shorthand for MustLocalize
func MustT(messageID string, templateData map[string]any) string {
	return GetLocalizer().MustLocalize(messageID, templateData)
}

// RegisterPseudoLocaleForTesting registers lang (a tag with CLDR plural rules
// that no shipped locale uses, such as "it" -- private-use tags like "qaa" have
// no plural rule and are rejected) whose messages are exactly overrides, then
// switches the process-global localizer to it; every other message ID falls
// back to the fallback language. It exists so a test can CHANGE a translation
// and prove that code which used to classify errors by their translated text no
// longer depends on it (#2905): the shipped locales leave several error
// messages in English, so flipping to one of them proves nothing. The returned
// func switches back to the language that was active before the call.
func RegisterPseudoLocaleForTesting(lang string, overrides map[string]string) (restore func(), err error) {
	l := GetLocalizer()
	tag, err := language.Parse(lang)
	if err != nil {
		return nil, fmt.Errorf("pseudo-locale %q: %w", lang, err)
	}
	msgs := make([]*i18n.Message, 0, len(overrides))
	for id, text := range overrides {
		msgs = append(msgs, &i18n.Message{ID: id, One: text, Other: text})
	}
	if err := l.bundle.AddMessages(tag, msgs...); err != nil {
		return nil, fmt.Errorf("pseudo-locale %q: %w", lang, err)
	}
	l.mutex.RLock()
	prev := l.currentLang
	l.mutex.RUnlock()
	l.SetLanguage(lang)
	return func() { l.SetLanguage(prev) }, nil
}

// ResetForTesting resets the global i18n state for testing purposes
func ResetForTesting() {
	globMu.Lock()
	globalLocalizer = nil
	once = sync.Once{}
	globMu.Unlock()
}
