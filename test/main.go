package main

import (
    "fmt"
    "log"
    "time"

    "github.com/debianrose/deencgo"
)

func main() {
    fmt.Println("╔════════════════════════════════════════╗")
    fmt.Println("║     DeENC - словарное шифрование       ║")
    fmt.Println("║           debianrose edition            ║")
    fmt.Println("╚════════════════════════════════════════╝")

    // Создаем конфиг
    config := &deencgo.DeENCConfig{
        ReplacementChance: 70,
        CaseChangeChance:  40,
        UseSeed:           true,
        Seed:              12345,
        DictionaryFile:    "wordzzzz.txt",
        CacheSizeKB:       512,
    }

    // Создаем шифратор с конфигом
    deenc, err := deencgo.NewDeENC(config)
    if err != nil {
        log.Fatal(err)
    }
    defer deenc.Close()

    // Тестовые данные
    original := []byte("Привет, мир! Это тест DeENC шифрования.")

    fmt.Printf("\n📦 Исходные данные (%d байт):\n", len(original))
    fmt.Printf("   %s\n", original)

    // Шифруем
    start := time.Now()
    encryptedWords, err := deenc.Encrypt(original)
    if err != nil {
        log.Fatal(err)
    }
    encTime := time.Since(start)

    fmt.Printf("\n🔐 Зашифровано (%d слов):\n", len(encryptedWords))
    fmt.Printf("   Первые 3 слова:\n")
    for i := 0; i < 3 && i < len(encryptedWords); i++ {
        fmt.Printf("   %d. %s\n", i+1, encryptedWords[i])
    }
    fmt.Printf("   ... и еще %d слов\n", len(encryptedWords)-3)
    fmt.Printf("   Время: %v\n", encTime)

    // Расшифровываем
    start = time.Now()
    decrypted, err := deenc.Decrypt(encryptedWords)
    if err != nil {
        log.Fatal(err)
    }
    decTime := time.Since(start)

    fmt.Printf("\n🔓 Расшифровано:\n")
    fmt.Printf("   %s\n", decrypted)
    fmt.Printf("   Время: %v\n", decTime)

    // Проверка
    if string(decrypted) == string(original) {
        fmt.Printf("\n✅ УСПЕХ! Данные восстановлены полностью.\n")
    } else {
        fmt.Printf("\n❌ ОШИБКА! Данные не совпадают.\n")
    }

    // Статистика
    stats := deenc.Stats()
    fmt.Printf("\n📊 Статистика:\n")
    fmt.Printf("   Базовых слов: %d\n", stats["dictionary_size"])
    fmt.Printf("   Вариантов в обратном словаре: %d\n", stats["reverse_map_size"])
    fmt.Printf("   Покрытие: %.2f%%\n", stats["coverage"].(float64)*100)

    // Тест на варианты
    fmt.Printf("\n🎨 Варианты слова \"coffee\":\n")
    variants, _ := deenc.GenerateVariants("coffee", 5)
    for i, v := range variants {
        fmt.Printf("   %d. %s\n", i+1, v)
    }
}
