package i18n

import (
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestFullTranslationWorkflow(t *testing.T) {
	// Reset global state
	globalLocalizer = nil
	once = sync.Once{}

	// Test complete workflow from config to translation
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	// Initialize system
	err := Initialize(cfg)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	// Test that all message categories work
	testCases := []struct {
		category  string
		messageID string
		expected  string
	}{
		{"Welcome", "Welcome", "Welcome to Keyorix!"},
		{"Error", "ErrorUserNotFound", "User not found"},
		{"Success", "SuccessSecretCreated", "Secret created successfully"},
		{"Label", "LabelName", "Name"},
		{"Button", "ButtonCreate", "Create"},
	}

	for _, tc := range testCases {
		t.Run(tc.category, func(t *testing.T) {
			result := T(tc.messageID, nil)
			if result != tc.expected {
				t.Errorf("T(%s) = %v, expected %v", tc.messageID, result, tc.expected)
			}
		})
	}
}

func TestAllSupportedLanguages(t *testing.T) {
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

	// Test all supported languages
	languages := []struct {
		code    string
		welcome string
		error   string
		success string
		label   string
		button  string
	}{
		{
			code:    "en",
			welcome: "Welcome to Keyorix!",
			error:   "User not found",
			success: "Secret created successfully",
			label:   "Name",
			button:  "Create",
		},
		{
			code:    "ru",
			welcome: "Добро пожаловать в Keyorix!",
			error:   "Пользователь не найден",
			success: "Секрет успешно создан",
			label:   "Имя",
			button:  "Создать",
		},
		{
			code:    "es",
			welcome: "¡Bienvenido a Keyorix!",
			error:   "Usuario no encontrado",
			success: "Secreto creado con éxito",
			label:   "Nombre",
			button:  "Crear",
		},
		{
			code:    "fr",
			welcome: "Bienvenue sur Keyorix !",
			error:   "Utilisateur non trouvé",
			success: "Secret créé avec succès",
			label:   "Nom",
			button:  "Créer",
		},
		{
			code:    "de",
			welcome: "Willkommen bei Keyorix!",
			error:   "Benutzer nicht gefunden",
			success: "Geheimnis erfolgreich erstellt",
			label:   "Name",
			button:  "Erstellen",
		},
	}

	for _, lang := range languages {
		t.Run(lang.code, func(t *testing.T) {
			localizer.SetLanguage(lang.code)

			// Test different message categories
			testCases := []struct {
				messageID string
				expected  string
			}{
				{"Welcome", lang.welcome},
				{"ErrorUserNotFound", lang.error},
				{"SuccessSecretCreated", lang.success},
				{"LabelName", lang.label},
				{"ButtonCreate", lang.button},
			}

			for _, tc := range testCases {
				result := localizer.Localize(tc.messageID, nil)
				if result != tc.expected {
					t.Errorf("Language %s: Localize(%s) = %v, expected %v",
						lang.code, tc.messageID, result, tc.expected)
				}
			}
		})
	}
}

func TestFallbackLanguageBehavior(t *testing.T) {
	// Reset global state
	globalLocalizer = nil
	once = sync.Once{}

	// Test with Spanish primary and English fallback
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "es",
			FallbackLanguage: "en",
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
		t.Errorf("Spanish message: Localize() = %v, expected %v", result, expected)
	}

	// Test non-existing message (should return messageID as fallback)
	result = localizer.Localize("NonExistentMessage", nil)
	expected = "NonExistentMessage"
	if result != expected {
		t.Errorf("Non-existing message: Localize() = %v, expected %v", result, expected)
	}
}

func TestConfigurationChanges(t *testing.T) {
	// Test different configuration scenarios
	testConfigs := []struct {
		name     string
		config   *config.Config
		expected string
	}{
		{
			name: "English primary",
			config: &config.Config{
				Locale: config.LocaleConfig{
					Language:         "en",
					FallbackLanguage: "en",
				},
			},
			expected: "Welcome to Keyorix!",
		},
		{
			name: "Russian primary with English fallback",
			config: &config.Config{
				Locale: config.LocaleConfig{
					Language:         "ru",
					FallbackLanguage: "en",
				},
			},
			expected: "Добро пожаловать в Keyorix!",
		},
		{
			name: "Empty language defaults to English",
			config: &config.Config{
				Locale: config.LocaleConfig{
					Language:         "",
					FallbackLanguage: "",
				},
			},
			expected: "Welcome to Keyorix!",
		},
	}

	for _, tc := range testConfigs {
		t.Run(tc.name, func(t *testing.T) {
			// Reset global state
			globalLocalizer = nil
			once = sync.Once{}

			err := Initialize(tc.config)
			if err != nil {
				t.Fatalf("Initialize() failed: %v", err)
			}

			result := T("Welcome", nil)
			if result != tc.expected {
				t.Errorf("T() = %v, expected %v", result, tc.expected)
			}
		})
	}
}

func TestLanguageSwitching(t *testing.T) {
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

	// Test switching between languages
	languages := []struct {
		code     string
		expected string
	}{
		{"en", "Welcome to Keyorix!"},
		{"ru", "Добро пожаловать в Keyorix!"},
		{"es", "¡Bienvenido a Keyorix!"},
		{"fr", "Bienvenue sur Keyorix !"},
		{"de", "Willkommen bei Keyorix!"},
		{"en", "Welcome to Keyorix!"}, // Switch back to English
	}

	for i, lang := range languages {
		t.Run(lang.code+"_"+string(rune('0'+i)), func(t *testing.T) {
			localizer.SetLanguage(lang.code)
			result := localizer.Localize("Welcome", nil)
			if result != lang.expected {
				t.Errorf("After SetLanguage(%s): Localize() = %v, expected %v",
					lang.code, result, lang.expected)
			}
		})
	}
}

func TestMessageCompleteness(t *testing.T) {
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

	// Test that key messages exist in all languages
	keyMessages := []string{
		"Welcome",
		"ErrorUserNotFound",
		"ErrorInvalidCredentials",
		"ErrorUnauthorized",
		"ErrorInternalServer",
		"SuccessSecretCreated",
		"SuccessSecretUpdated",
		"SuccessSecretDeleted",
		"LabelName",
		"LabelValue",
		"LabelEmail",
		"ButtonCreate",
		"ButtonUpdate",
		"ButtonDelete",
	}

	languages := []string{"en", "ru", "es", "fr", "de"}

	for _, lang := range languages {
		t.Run("completeness_"+lang, func(t *testing.T) {
			localizer.SetLanguage(lang)

			for _, messageID := range keyMessages {
				result := localizer.Localize(messageID, nil)
				// If translation is missing, it returns the messageID
				if result == messageID {
					t.Errorf("Missing translation for %s in language %s", messageID, lang)
				}
				if result == "" {
					t.Errorf("Empty translation for %s in language %s", messageID, lang)
				}
			}
		})
	}
}

func TestConcurrentLanguageSwitching(t *testing.T) {
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

	// Test concurrent language switching and translation
	languages := []string{"en", "ru", "es", "fr", "de"}
	done := make(chan bool)

	for i := range 5 {
		go func(langIndex int) {
			lang := languages[langIndex]
			for range 50 {
				localizer.SetLanguage(lang)
				result := localizer.Localize("Welcome", nil)
				if result == "" {
					t.Errorf("Empty result for language %s in concurrent test", lang)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for range 5 {
		<-done
	}
}

func TestErrorMessageTranslations(t *testing.T) {
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

	// Test error messages in different languages
	errorTests := []struct {
		lang      string
		messageID string
		expected  string
	}{
		{"en", "ErrorUserNotFound", "User not found"},
		{"ru", "ErrorUserNotFound", "Пользователь не найден"},
		{"es", "ErrorUserNotFound", "Usuario no encontrado"},
		{"fr", "ErrorUserNotFound", "Utilisateur non trouvé"},
		{"de", "ErrorUserNotFound", "Benutzer nicht gefunden"},
	}

	for _, test := range errorTests {
		t.Run(test.lang+"_"+test.messageID, func(t *testing.T) {
			localizer.SetLanguage(test.lang)
			result := localizer.Localize(test.messageID, nil)
			if result != test.expected {
				t.Errorf("Language %s: Localize(%s) = %v, expected %v",
					test.lang, test.messageID, result, test.expected)
			}
		})
	}
}

func TestSuccessMessageTranslations(t *testing.T) {
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

	// Test success messages in different languages
	successTests := []struct {
		lang      string
		messageID string
		expected  string
	}{
		{"en", "SuccessSecretCreated", "Secret created successfully"},
		{"ru", "SuccessSecretCreated", "Секрет успешно создан"},
		{"es", "SuccessSecretCreated", "Secreto creado con éxito"},
		{"fr", "SuccessSecretCreated", "Secret créé avec succès"},
		{"de", "SuccessSecretCreated", "Geheimnis erfolgreich erstellt"},
	}

	for _, test := range successTests {
		t.Run(test.lang+"_"+test.messageID, func(t *testing.T) {
			localizer.SetLanguage(test.lang)
			result := localizer.Localize(test.messageID, nil)
			if result != test.expected {
				t.Errorf("Language %s: Localize(%s) = %v, expected %v",
					test.lang, test.messageID, result, test.expected)
			}
		})
	}
}
