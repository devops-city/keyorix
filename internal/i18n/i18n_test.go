package i18n

import (
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestInitialize(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		expectError bool
	}{
		{
			name: "valid config with English",
			config: &config.Config{
				Locale: config.LocaleConfig{
					Language:         "en",
					FallbackLanguage: "en",
				},
			},
			expectError: false,
		},
		{
			name: "valid config with Russian",
			config: &config.Config{
				Locale: config.LocaleConfig{
					Language:         "ru",
					FallbackLanguage: "en",
				},
			},
			expectError: false,
		},
		{
			name: "empty language defaults to English",
			config: &config.Config{
				Locale: config.LocaleConfig{
					Language:         "",
					FallbackLanguage: "",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global state
			globalLocalizer = nil
			once = sync.Once{}

			err := Initialize(tt.config)
			if (err != nil) != tt.expectError {
				t.Errorf("Initialize() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError {
				if globalLocalizer == nil {
					t.Error("globalLocalizer should not be nil after successful initialization")
				}
			}
		})
	}
}

func TestGetLocalizer(t *testing.T) {
	// Reset global state
	globalLocalizer = nil
	once = sync.Once{}

	// Test panic when not initialized
	defer func() {
		if recover() == nil {
			t.Error("GetLocalizer() should panic when not initialized")
		}
	}()
	GetLocalizer()
}

func TestGetLocalizerAfterInit(t *testing.T) {
	// Reset global state
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	localizer := GetLocalizer()
	if localizer == nil {
		t.Error("GetLocalizer() should return non-nil localizer after initialization")
	}
}

func TestLocalize(t *testing.T) {
	// Reset global state and initialize
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	localizer := GetLocalizer()

	tests := []struct {
		name         string
		messageID    string
		templateData map[string]any
		expected     string
	}{
		{
			name:         "existing message",
			messageID:    "Welcome",
			templateData: nil,
			expected:     "Welcome to Keyorix!",
		},
		{
			name:         "non-existing message returns messageID",
			messageID:    "NonExistentMessage",
			templateData: nil,
			expected:     "NonExistentMessage",
		},
		{
			name:         "error message",
			messageID:    "ErrorUserNotFound",
			templateData: nil,
			expected:     "User not found",
		},
		{
			name:         "success message",
			messageID:    "SuccessSecretCreated",
			templateData: nil,
			expected:     "Secret created successfully",
		},
		{
			name:         "label message",
			messageID:    "LabelName",
			templateData: nil,
			expected:     "Name",
		},
		{
			name:         "button message",
			messageID:    "ButtonCreate",
			templateData: nil,
			expected:     "Create",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := localizer.Localize(tt.messageID, tt.templateData)
			if result != tt.expected {
				t.Errorf("Localize() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestMustLocalize(t *testing.T) {
	// Reset global state and initialize
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	localizer := GetLocalizer()

	t.Run("existing message", func(t *testing.T) {
		result := localizer.MustLocalize("Welcome", nil)
		expected := "Welcome to Keyorix!" //nolint:goconst
		if result != expected {
			t.Errorf("MustLocalize() = %v, expected %v", result, expected)
		}
	})

	t.Run("non-existing message panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("MustLocalize() should panic for non-existing message")
			}
		}()
		localizer.MustLocalize("NonExistentMessage", nil)
	})
}

func TestSetLanguage(t *testing.T) {
	// Reset global state and initialize
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	localizer := GetLocalizer()

	// Test initial language
	if localizer.currentLang != "en" {
		t.Errorf("Initial language = %v, expected en", localizer.currentLang)
	}

	// Test changing language
	localizer.SetLanguage("ru")
	if localizer.currentLang != "ru" {
		t.Errorf("Language after SetLanguage() = %v, expected ru", localizer.currentLang)
	}

	// Test translation in new language
	result := localizer.Localize("Welcome", nil)
	expected := "Добро пожаловать в Keyorix!"
	if result != expected {
		t.Errorf("Localize() after SetLanguage() = %v, expected %v", result, expected)
	}
}

func TestTFunction(t *testing.T) {
	// Reset global state and initialize
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	result := T("Welcome", nil)
	expected := "Welcome to Keyorix!"
	if result != expected {
		t.Errorf("T() = %v, expected %v", result, expected)
	}
}

func TestMustTFunction(t *testing.T) {
	// Reset global state and initialize
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	t.Run("existing message", func(t *testing.T) {
		result := MustT("Welcome", nil)
		expected := "Welcome to Keyorix!"
		if result != expected {
			t.Errorf("MustT() = %v, expected %v", result, expected)
		}
	})

	t.Run("non-existing message panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("MustT() should panic for non-existing message")
			}
		}()
		MustT("NonExistentMessage", nil)
	})
}

func TestMultipleLanguages(t *testing.T) {
	// Reset global state and initialize
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	localizer := GetLocalizer()

	languages := []struct {
		code     string
		expected string
	}{
		{"en", "Welcome to Keyorix!"},
		{"ru", "Добро пожаловать в Keyorix!"},
		{"es", "¡Bienvenido a Keyorix!"},
		{"fr", "Bienvenue sur Keyorix !"},
		{"de", "Willkommen bei Keyorix!"},
	}

	for _, lang := range languages {
		t.Run(lang.code, func(t *testing.T) {
			localizer.SetLanguage(lang.code)
			result := localizer.Localize("Welcome", nil)
			if result != lang.expected {
				t.Errorf("Localize() for %s = %v, expected %v", lang.code, result, lang.expected)
			}
		})
	}
}

func TestFallbackBehavior(t *testing.T) {
	// Reset global state and initialize
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "es", // Spanish as primary
			FallbackLanguage: "en", // English as fallback
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	localizer := GetLocalizer()

	// Test existing Spanish message
	result := localizer.Localize("Welcome", nil)
	expected := "¡Bienvenido a Keyorix!"
	if result != expected {
		t.Errorf("Localize() for existing Spanish message = %v, expected %v", result, expected)
	}

	// Test non-existing message (should return messageID as fallback)
	result = localizer.Localize("NonExistentMessage", nil)
	expected = "NonExistentMessage"
	if result != expected {
		t.Errorf("Localize() for non-existing message = %v, expected %v", result, expected)
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Reset global state and initialize
	globalLocalizer = nil
	once = sync.Once{}

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	localizer := GetLocalizer()

	// Test concurrent access to localization
	done := make(chan bool)
	for range 10 {
		go func() {
			for range 100 {
				result := localizer.Localize("Welcome", nil)
				if result == "" {
					t.Errorf("Localize() returned empty string in concurrent access")
				}
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}
}
