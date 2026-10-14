package i18n

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// BenchmarkInitialize benchmarks the initialization process
func BenchmarkInitialize(b *testing.B) {
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset global state for each iteration
		globalLocalizer = nil
		once = sync.Once{}

		err := Initialize(cfg)
		if err != nil {
			b.Fatalf("Initialize failed: %v", err)
		}
	}
}

// BenchmarkLocalize benchmarks basic translation lookup
func BenchmarkLocalize(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = localizer.Localize("Welcome", nil)
	}
}

// BenchmarkLocalizeWithTemplateData benchmarks translation with template data
func BenchmarkLocalizeWithTemplateData(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()
	templateData := map[string]any{
		"Name":  "John",
		"Count": 42,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = localizer.Localize("Welcome", templateData)
	}
}

// BenchmarkTFunction benchmarks the global T function
func BenchmarkTFunction(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = T("Welcome", nil)
	}
}

// BenchmarkSetLanguage benchmarks language switching
func BenchmarkSetLanguage(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()
	languages := []string{"en", "ru", "es", "fr", "de"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lang := languages[i%len(languages)]
		localizer.SetLanguage(lang)
	}
}

// BenchmarkConcurrentLocalize benchmarks concurrent translation access
func BenchmarkConcurrentLocalize(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = localizer.Localize("Welcome", nil)
		}
	})
}

// BenchmarkConcurrentLanguageSwitching benchmarks concurrent language switching
func BenchmarkConcurrentLanguageSwitching(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()
	languages := []string{"en", "ru", "es", "fr", "de"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			lang := languages[i%len(languages)]
			localizer.SetLanguage(lang)
			_ = localizer.Localize("Welcome", nil)
			i++
		}
	})
}

// BenchmarkMultipleLanguages benchmarks translation in different languages
func BenchmarkMultipleLanguages(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()
	languages := []string{"en", "ru", "es", "fr", "de"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lang := languages[i%len(languages)]
		localizer.SetLanguage(lang)
		_ = localizer.Localize("Welcome", nil)
	}
}

// BenchmarkMissingTranslation benchmarks fallback behavior for missing translations
func BenchmarkMissingTranslation(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = localizer.Localize("NonExistentMessage", nil)
	}
}

// BenchmarkLargeTemplateData benchmarks translation with large template data
func BenchmarkLargeTemplateData(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()

	// Create large template data
	templateData := make(map[string]any)
	for i := range 100 {
		templateData[fmt.Sprintf("Key%d", i)] = fmt.Sprintf("Value%d", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = localizer.Localize("Welcome", templateData)
	}
}

// BenchmarkMemoryUsage measures memory allocation during translation
func BenchmarkMemoryUsage(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = localizer.Localize("Welcome", nil)
	}
}

// BenchmarkStartupTime measures the time to initialize the i18n system
func BenchmarkStartupTime(b *testing.B) {
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Reset global state
		globalLocalizer = nil
		once = sync.Once{}

		start := time.Now()
		err := Initialize(cfg)
		if err != nil {
			b.Fatalf("Initialize failed: %v", err)
		}
		duration := time.Since(start)

		// Report custom metric
		b.ReportMetric(float64(duration.Nanoseconds()), "ns/init")
	}
}

// Performance test for realistic usage patterns
func BenchmarkRealisticUsage(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()

	// Common message types used in a typical application
	messages := []string{
		"Welcome",
		"ErrorUserNotFound",
		"ErrorInvalidCredentials",
		"SuccessSecretCreated",
		"SuccessSecretUpdated",
		"LabelName",
		"LabelEmail",
		"ButtonCreate",
		"ButtonUpdate",
		"ButtonDelete",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		messageID := messages[i%len(messages)]
		_ = localizer.Localize(messageID, nil)
	}
}

// Benchmark comparison between T() and direct Localize()
func BenchmarkTFunctionVsLocalize(b *testing.B) {
	// Setup
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
		b.Fatalf("Initialize failed: %v", err)
	}

	localizer := GetLocalizer()

	b.Run("T_Function", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = T("Welcome", nil)
		}
	})

	b.Run("Direct_Localize", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = localizer.Localize("Welcome", nil)
		}
	})
}
