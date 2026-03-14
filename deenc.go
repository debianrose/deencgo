package deencgo

/*
#cgo CFLAGS: -I./leetgen
#cgo LDFLAGS: -L./leetgen -lleetgen -lm

#include "leet_generator.h"
#include <stdlib.h>
#include <locale.h>
#include <stdint.h>
*/
import "C"
import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const currentVersion = 2

type LeetError int

const (
	LeetOK          LeetError = 0
	LeetErrMemory   LeetError = 1
	LeetErrNullPtr  LeetError = 2
	LeetErrEncoding LeetError = 3
)

func (e LeetError) String() string {
	switch e {
	case LeetOK:
		return "ok"
	case LeetErrMemory:
		return "memory allocation failed"
	case LeetErrNullPtr:
		return "null pointer"
	case LeetErrEncoding:
		return "encoding failed"
	default:
		return "unknown error"
	}
}

func leetErr(context string) error {
	code := LeetError(C.leet_get_last_error())
	msg := C.GoString(C.leet_get_last_error_msg())
	C.leet_clear_error()
	if msg == "" {
		msg = code.String()
	}
	return fmt.Errorf("%s: leet error %d (%s)", context, int(code), msg)
}

type DeENCConfig struct {
	ReplacementChance  int
	CaseChangeChance   int
	UseSeed            bool
	Seed               uint32
	DictionaryFile     string
	DictionaryKey      []byte
	CacheSizeKB        int
	MaxVariantsPerByte int
	EnableMetrics      bool
	EnablePool         bool
}

func (c *DeENCConfig) Validate() error {
	if c == nil {
		return errors.New("config cannot be nil")
	}
	if c.DictionaryFile == "" {
		return errors.New("dictionary file is required")
	}
	if c.ReplacementChance < 0 || c.ReplacementChance > 100 {
		return fmt.Errorf("replacement chance must be 0-100, got %d", c.ReplacementChance)
	}
	if c.CaseChangeChance < 0 || c.CaseChangeChance > 100 {
		return fmt.Errorf("case change chance must be 0-100, got %d", c.CaseChangeChance)
	}
	if c.CacheSizeKB < 0 {
		return fmt.Errorf("cache size cannot be negative")
	}
	if c.MaxVariantsPerByte <= 0 {
		c.MaxVariantsPerByte = 50
	}
	if c.MaxVariantsPerByte > 1000 {
		return fmt.Errorf("max variants per byte too high: %d", c.MaxVariantsPerByte)
	}
	return nil
}

func DefaultConfig() *DeENCConfig {
	return &DeENCConfig{
		ReplacementChance:  70,
		CaseChangeChance:   40,
		UseSeed:            false,
		CacheSizeKB:        512,
		MaxVariantsPerByte: 50,
		EnableMetrics:      true,
		EnablePool:         true,
	}
}

type DeENCMetrics struct {
	mu             sync.Mutex
	encryptCount   int64
	decryptCount   int64
	encryptBytes   int64
	decryptBytes   int64
	encryptErrors  int64
	decryptErrors  int64
	encryptTime    time.Duration
	decryptTime    time.Duration
	maxEncryptTime time.Duration
	maxDecryptTime time.Duration
	cacheHits      int64
	cacheMisses    int64
	startTime      time.Time
}

func (m *DeENCMetrics) recordEncrypt(start time.Time, bytes int64, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.encryptCount++
	m.encryptBytes += bytes
	d := time.Since(start)
	m.encryptTime += d
	if d > m.maxEncryptTime {
		m.maxEncryptTime = d
	}
	if err != nil {
		m.encryptErrors++
	}
}

func (m *DeENCMetrics) recordDecrypt(start time.Time, bytes int64, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decryptCount++
	m.decryptBytes += bytes
	d := time.Since(start)
	m.decryptTime += d
	if d > m.maxDecryptTime {
		m.maxDecryptTime = d
	}
	if err != nil {
		m.decryptErrors++
	}
}

func (m *DeENCMetrics) recordCacheHit() {
	m.mu.Lock()
	m.cacheHits++
	m.mu.Unlock()
}

func (m *DeENCMetrics) recordCacheMiss() {
	m.mu.Lock()
	m.cacheMisses++
	m.mu.Unlock()
}

func (m *DeENCMetrics) Snapshot() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	uptime := time.Since(m.startTime)
	encCount := m.encryptCount
	if encCount == 0 {
		encCount = 1
	}
	decCount := m.decryptCount
	if decCount == 0 {
		decCount = 1
	}
	total := m.cacheHits + m.cacheMisses
	if total == 0 {
		total = 1
	}
	return map[string]interface{}{
		"encrypt_count":       m.encryptCount,
		"decrypt_count":       m.decryptCount,
		"encrypt_bytes":       m.encryptBytes,
		"decrypt_bytes":       m.decryptBytes,
		"encrypt_errors":      m.encryptErrors,
		"decrypt_errors":      m.decryptErrors,
		"avg_encrypt_time_ms": float64(m.encryptTime) / float64(time.Millisecond) / float64(encCount),
		"avg_decrypt_time_ms": float64(m.decryptTime) / float64(time.Millisecond) / float64(decCount),
		"max_encrypt_time_ms": float64(m.maxEncryptTime) / float64(time.Millisecond),
		"max_decrypt_time_ms": float64(m.maxDecryptTime) / float64(time.Millisecond),
		"cache_hits":          m.cacheHits,
		"cache_misses":        m.cacheMisses,
		"cache_hit_ratio":     float64(m.cacheHits) / float64(total),
		"uptime_seconds":      uptime.Seconds(),
	}
}

type DeENC struct {
	gen           *C.LeetGenerator
	wordDict      []string
	reverse       map[string]byte
	reverseHashes map[uint64]byte
	key           []byte
	mu            sync.RWMutex
	config        *DeENCConfig
	closed        bool
	metrics       *DeENCMetrics
	wordPool      *sync.Pool
	cWords        []*C.char
	cWordsInit    bool
}

type EncryptedData struct {
	Version   int      `json:"v"`
	IV        string   `json:"iv"`
	Words     []string `json:"w"`
	AuthTag   string   `json:"t"`
	Timestamp int64    `json:"ts"`
}

type KeyManager struct {
	currentKey []byte
	oldKeys    map[string][]byte
	keyExpiry  time.Time
	mu         sync.RWMutex
	maxOldKeys int
}

type DeENCWriter struct {
	deenc    *DeENC
	writer   io.Writer
	buffer   []byte
	position int
	closed   bool
	mu       sync.Mutex
}

type DeENCReader struct {
	deenc    *DeENC
	reader   io.Reader
	pending  []byte
	lineBuf  strings.Builder
	mu       sync.Mutex
}

type BatchResult struct {
	Results [][]string
	Errors  []error
	TimeMs  int64
}

func NewDeENC(config *DeENCConfig) (*DeENC, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	cLocale := C.CString("")
	C.setlocale(C.LC_ALL, cLocale)
	C.free(unsafe.Pointer(cLocale))

	words, err := loadWords(config.DictionaryFile, config.DictionaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load words: %w", err)
	}
	if len(words) < 256 {
		return nil, fmt.Errorf("need at least 256 words, got %d", len(words))
	}

	gen := C.leet_create_generator()
	if gen == nil {
		return nil, leetErr("leet_create_generator")
	}

	C.leet_set_replacement_chance(gen, C.int(config.ReplacementChance))
	C.leet_set_case_chance(gen, C.int(config.CaseChangeChance))
	C.leet_set_cache_size(gen, C.int(config.CacheSizeKB))

	if config.UseSeed {
		C.leet_set_seed(gen, C.uint(config.Seed))
	} else {
		C.leet_randomize_seed(gen)
	}

	d := &DeENC{
		gen:           gen,
		wordDict:      make([]string, 256),
		reverse:       make(map[string]byte),
		reverseHashes: make(map[uint64]byte),
		config:        config,
		closed:        false,
		metrics:       &DeENCMetrics{startTime: time.Now()},
	}

	if config.EnablePool {
		d.wordPool = &sync.Pool{
			New: func() interface{} {
				return make([]string, 0, 1024)
			},
		}
	}

	for i := 0; i < 256; i++ {
		d.wordDict[i] = words[i]
	}

	if err := d.buildReverseDict(config.MaxVariantsPerByte); err != nil {
		d.Close()
		return nil, fmt.Errorf("failed to build reverse dictionary: %w", err)
	}

	if err := d.initCWords(); err != nil {
		d.Close()
		return nil, fmt.Errorf("failed to initialize C words: %w", err)
	}

	return d, nil
}

func NewDeENCWithKey(config *DeENCConfig, key []byte) (*DeENC, error) {
	if len(key) == 0 {
		return nil, errors.New("key cannot be empty")
	}
	d, err := NewDeENC(config)
	if err != nil {
		return nil, err
	}
	d.key = make([]byte, len(key))
	copy(d.key, key)
	return d, nil
}

func loadWords(filename string, dictKey []byte) ([]string, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if dictKey != nil {
		raw, err = aesGCMDecrypt(dictKey, raw)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt dictionary: %w", err)
		}
	}

	var words []string
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}

func EncryptDictionaryFile(srcPath, dstPath string, key []byte) error {
	plain, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	enc, err := aesGCMEncrypt(key, plain)
	if err != nil {
		return err
	}
	return os.WriteFile(dstPath, enc, 0600)
}

func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	k := deriveKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...), nil
}

func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	k := deriveKey(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

func deriveKey(key []byte) []byte {
	h := sha256.Sum256(key)
	return h[:]
}

func (d *DeENC) initCWords() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cWordsInit {
		return nil
	}
	d.cWords = make([]*C.char, 256)
	for i, word := range d.wordDict {
		cw := C.CString(word)
		if cw == nil {
			for j := 0; j < i; j++ {
				C.free(unsafe.Pointer(d.cWords[j]))
			}
			return fmt.Errorf("failed to allocate C string for word %d", i)
		}
		d.cWords[i] = cw
	}
	d.cWordsInit = true
	return nil
}

func (d *DeENC) isClosed() bool {
	return d.closed
}

func (d *DeENC) checkClosed() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return errors.New("deenc is closed")
	}
	return nil
}

func (d *DeENC) buildReverseDict(variantsPerByte int) error {
	for b := 0; b < 256; b++ {
		cw := C.CString(d.wordDict[b])
		if cw == nil {
			return fmt.Errorf("failed to allocate C string for byte %d", b)
		}

		buf := [5]byte{
			byte(d.config.Seed),
			byte(d.config.Seed >> 8),
			byte(d.config.Seed >> 16),
			byte(d.config.Seed >> 24),
			byte(b),
		}
		h := sha256.Sum256(buf[:])
		seedInt := uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
		C.leet_set_seed(d.gen, C.uint(seedInt))

		cResult := C.leet_encrypt_word(d.gen, cw)
		if cResult != nil {
			cUtf8 := C.leet_unicode_to_utf8(cResult)
			C.free(unsafe.Pointer(cResult))
			if cUtf8 != nil {
				lw := C.GoString(cUtf8)
				C.free(unsafe.Pointer(cUtf8))
				d.reverse[lw] = byte(b)
				h := fnv.New64a()
				h.Write([]byte(lw))
				d.reverseHashes[h.Sum64()] = byte(b)
			}
		}

		C.free(unsafe.Pointer(cw))
	}
	return nil
}

func (d *DeENC) encryptByteUnsafe(b byte, position int) (string, error) {
	if !d.cWordsInit || int(b) >= len(d.cWords) {
		return "", fmt.Errorf("invalid byte value: %d", b)
	}

	var seedInt uint32
	if d.key != nil {
		buf := make([]byte, 0, len(d.key)+1)
		buf = append(buf, d.key...)
		buf = append(buf, b)
		h := sha256.Sum256(buf)
		seedInt = uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
	} else {
		buf := [5]byte{
			byte(d.config.Seed),
			byte(d.config.Seed >> 8),
			byte(d.config.Seed >> 16),
			byte(d.config.Seed >> 24),
			b,
		}
		h := sha256.Sum256(buf[:])
		seedInt = uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
	}
	C.leet_set_seed(d.gen, C.uint(seedInt))

	cResult := C.leet_encrypt_word(d.gen, d.cWords[b])
	if cResult == nil {
		return "", leetErr(fmt.Sprintf("leet_encrypt_word byte=%d", b))
	}
	defer C.free(unsafe.Pointer(cResult))

	cUtf8 := C.leet_unicode_to_utf8(cResult)
	if cUtf8 == nil {
		return "", leetErr(fmt.Sprintf("leet_unicode_to_utf8 byte=%d", b))
	}
	defer C.free(unsafe.Pointer(cUtf8))
	return C.GoString(cUtf8), nil
}

func (d *DeENC) Encrypt(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, errors.New("no data to encrypt")
	}

	start := time.Now()
	var retErr error
	defer func() {
		if d.config.EnableMetrics {
			d.metrics.recordEncrypt(start, int64(len(data)), retErr)
		}
	}()

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.isClosed() {
		retErr = errors.New("deenc is closed")
		return nil, retErr
	}

	var words []string
	if d.config.EnablePool && d.wordPool != nil {
		pooled := d.wordPool.Get().([]string)
		if cap(pooled) >= len(data) {
			words = pooled[:len(data)]
		} else {
			words = make([]string, len(data))
		}
		defer d.wordPool.Put(pooled[:0])
	} else {
		words = make([]string, len(data))
	}

	for i, b := range data {
		w, err := d.encryptByteUnsafe(b, i)
		if err != nil {
			retErr = err
			return nil, err
		}
		words[i] = w
	}

	result := make([]string, len(words))
	copy(result, words)
	return result, nil
}

func (d *DeENC) EncryptBatch(data [][]byte) (*BatchResult, error) {
	if err := d.checkClosed(); err != nil {
		return nil, err
	}
	start := time.Now()
	result := &BatchResult{
		Results: make([][]string, len(data)),
		Errors:  make([]error, len(data)),
	}
	for idx, chunk := range data {
		words, err := d.Encrypt(chunk)
		result.Results[idx] = words
		result.Errors[idx] = err
	}
	result.TimeMs = time.Since(start).Milliseconds()
	return result, nil
}

func (d *DeENC) EncryptString(data []byte, separator string) (string, error) {
	words, err := d.Encrypt(data)
	if err != nil {
		return "", err
	}
	return strings.Join(words, separator), nil
}

func (d *DeENC) Decrypt(words []string) ([]byte, error) {
	if len(words) == 0 {
		return nil, errors.New("no words to decrypt")
	}

	start := time.Now()
	var retErr error
	defer func() {
		if d.config.EnableMetrics {
			d.metrics.recordDecrypt(start, int64(len(words)), retErr)
		}
	}()

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.isClosed() {
		retErr = errors.New("deenc is closed")
		return nil, retErr
	}

	result := make([]byte, len(words))
	for i, word := range words {
		h := fnv.New64a()
		h.Write([]byte(word))
		hv := h.Sum64()

		b, ok := d.reverseHashes[hv]
		if !ok {
			if d.config.EnableMetrics {
				d.metrics.recordCacheMiss()
			}
			b, ok = d.reverse[word]
			if !ok {
				retErr = fmt.Errorf("unknown word at position %d: %s", i, word)
				return nil, retErr
			}
			if d.config.EnableMetrics {
				d.metrics.recordCacheHit()
			}
		} else if d.config.EnableMetrics {
			d.metrics.recordCacheHit()
		}
		result[i] = b
	}
	return result, nil
}

func (d *DeENC) DecryptString(encoded string, separator string) (string, error) {
	words := strings.Split(encoded, separator)
	data, err := d.Decrypt(words)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (d *DeENC) EncryptWithIV(data []byte, iv []byte) ([]string, error) {
	if len(iv) == 0 {
		iv = make([]byte, 16)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
	}
	if len(iv) < 1 {
		return nil, errors.New("iv too short")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.isClosed() {
		return nil, errors.New("deenc is closed")
	}

	result := make([]string, len(data)+1)

	w, err := d.encryptByteUnsafe(iv[0], -1)
	if err != nil {
		return nil, err
	}
	result[0] = w

	for i, b := range data {
		combined := make([]byte, 0, len(iv)+len(d.key)+2)
		combined = append(combined, iv...)
		if d.key != nil {
			combined = append(combined, d.key...)
		}
		combined = append(combined, b, byte(i))

		h := sha256.Sum256(combined)
		seedInt := uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
		C.leet_set_seed(d.gen, C.uint(seedInt))

		w, err = d.encryptByteUnsafe(b, i)
		if err != nil {
			return nil, err
		}
		result[i+1] = w
	}
	return result, nil
}

const hmacTagWords = 32

func (d *DeENC) EncryptWithAuth(data []byte) ([]string, []byte, error) {
	if err := d.checkClosed(); err != nil {
		return nil, nil, err
	}
	if d.key == nil {
		return nil, nil, errors.New("key required for authentication")
	}

	mac := hmac.New(sha256.New, d.key)
	mac.Write(data)
	authTag := mac.Sum(nil)

	words, err := d.Encrypt(data)
	if err != nil {
		return nil, nil, err
	}

	authWords, err := d.Encrypt(authTag)
	if err != nil {
		return nil, nil, err
	}

	return append(words, authWords...), authTag, nil
}

func (d *DeENC) DecryptWithAuth(words []string, expectedTag []byte) ([]byte, error) {
	if err := d.checkClosed(); err != nil {
		return nil, err
	}
	if d.key == nil {
		return nil, errors.New("key required for authentication")
	}
	if len(words) <= hmacTagWords {
		return nil, errors.New("invalid data: too few words")
	}

	dataWords := words[:len(words)-hmacTagWords]
	authWords := words[len(words)-hmacTagWords:]

	data, err := d.Decrypt(dataWords)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, d.key)
	mac.Write(data)
	computedTag := mac.Sum(nil)

	receivedTag, err := d.Decrypt(authWords)
	if err != nil {
		return nil, err
	}

	if !constantTimeCompare(computedTag, receivedTag) {
		return nil, errors.New("authentication failed")
	}
	if expectedTag != nil && !constantTimeCompare(computedTag, expectedTag) {
		return nil, errors.New("tag mismatch")
	}
	return data, nil
}

func (d *DeENC) EncryptSecure(data []byte) ([]byte, error) {
	if err := d.checkClosed(); err != nil {
		return nil, err
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	words, err := d.EncryptWithIV(data, iv)
	if err != nil {
		return nil, err
	}

	encData := EncryptedData{
		Version:   currentVersion,
		IV:        hex.EncodeToString(iv),
		Words:     words,
		Timestamp: time.Now().Unix(),
	}

	if d.key != nil {
		mac := hmac.New(sha256.New, d.key)
		mac.Write([]byte(strings.Join(words, "")))
		mac.Write(iv)
		encData.AuthTag = hex.EncodeToString(mac.Sum(nil))
	}

	return json.Marshal(encData)
}

func (d *DeENC) DecryptSecure(encrypted []byte) ([]byte, error) {
	if err := d.checkClosed(); err != nil {
		return nil, err
	}

	var encData EncryptedData
	if err := json.Unmarshal(encrypted, &encData); err != nil {
		return nil, err
	}

	if encData.Version != currentVersion {
		return nil, fmt.Errorf("unsupported version: %d", encData.Version)
	}

	iv, err := hex.DecodeString(encData.IV)
	if err != nil {
		return nil, err
	}

	if d.key != nil && encData.AuthTag != "" {
		mac := hmac.New(sha256.New, d.key)
		mac.Write([]byte(strings.Join(encData.Words, "")))
		mac.Write(iv)
		computed := mac.Sum(nil)
		computedHex := make([]byte, hex.EncodedLen(len(computed)))
		hex.Encode(computedHex, computed)

		if !constantTimeCompare(computedHex, []byte(encData.AuthTag)) {
			return nil, errors.New("authentication failed")
		}
	}

	return d.Decrypt(encData.Words)
}

func (d *DeENC) EncryptWithKeyRotation(data []byte) ([]byte, error) {
	if err := d.checkClosed(); err != nil {
		return nil, err
	}
	if d.key == nil {
		return nil, errors.New("no key set")
	}

	hash := sha256.Sum256(d.key)
	keyID := hex.EncodeToString(hash[:8])

	encrypted, err := d.EncryptSecure(data)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, len(keyID)+1+len(encrypted))
	result = append(result, []byte(keyID)...)
	result = append(result, ':')
	result = append(result, encrypted...)
	return result, nil
}

func (d *DeENC) GenerateVariants(word string, count int) ([]string, error) {
	if err := d.checkClosed(); err != nil {
		return nil, err
	}
	if count <= 0 {
		return nil, errors.New("count must be positive")
	}
	if count > 1000 {
		count = 1000
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	cw := C.CString(word)
	if cw == nil {
		return nil, errors.New("failed to allocate C string")
	}
	defer C.free(unsafe.Pointer(cw))

	results := make([]string, count)
	for i := 0; i < count; i++ {
		cResult := C.leet_encrypt_word(d.gen, cw)
		if cResult == nil {
			return nil, leetErr(fmt.Sprintf("leet_encrypt_word variant %d", i))
		}
		cUtf8 := C.leet_unicode_to_utf8(cResult)
		C.free(unsafe.Pointer(cResult))
		if cUtf8 == nil {
			return nil, leetErr(fmt.Sprintf("leet_unicode_to_utf8 variant %d", i))
		}
		results[i] = C.GoString(cUtf8)
		C.free(unsafe.Pointer(cUtf8))
	}
	return results, nil
}

func (d *DeENC) Stats() map[string]interface{} {
	if err := d.checkClosed(); err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := map[string]interface{}{
		"dictionary_size":     len(d.wordDict),
		"reverse_map_size":    len(d.reverse),
		"reverse_hashes_size": len(d.reverseHashes),
		"coverage":            float64(len(d.reverse)) / 256.0,
		"has_key":             d.key != nil,
		"closed":              d.closed,
	}
	if d.config.EnableMetrics {
		for k, v := range d.metrics.Snapshot() {
			stats["metric_"+k] = v
		}
	}
	return stats
}

func (d *DeENC) SetSeed(seed uint32) error {
	if err := d.checkClosed(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	C.leet_set_seed(d.gen, C.uint(seed))
	d.config.UseSeed = true
	d.config.Seed = seed
	return nil
}

func (d *DeENC) RandomizeSeed() error {
	if err := d.checkClosed(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	C.leet_randomize_seed(d.gen)
	d.config.UseSeed = false
	return nil
}

func (d *DeENC) SetReplacementChance(chance int) error {
	if err := d.checkClosed(); err != nil {
		return err
	}
	if chance < 0 || chance > 100 {
		return fmt.Errorf("chance must be 0-100, got %d", chance)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	C.leet_set_replacement_chance(d.gen, C.int(chance))
	d.config.ReplacementChance = chance
	return nil
}

func (d *DeENC) SetCaseChance(chance int) error {
	if err := d.checkClosed(); err != nil {
		return err
	}
	if chance < 0 || chance > 100 {
		return fmt.Errorf("chance must be 0-100, got %d", chance)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	C.leet_set_case_chance(d.gen, C.int(chance))
	d.config.CaseChangeChance = chance
	return nil
}

func (d *DeENC) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	if d.cWordsInit {
		for i := range d.cWords {
			if d.cWords[i] != nil {
				C.free(unsafe.Pointer(d.cWords[i]))
				d.cWords[i] = nil
			}
		}
		d.cWords = nil
		d.cWordsInit = false
	}

	if d.gen != nil {
		C.leet_destroy_generator(d.gen)
		d.gen = nil
	}

	for i := range d.key {
		d.key[i] = 0
	}

	d.wordDict = nil
	d.reverse = nil
	d.reverseHashes = nil
	d.key = nil
	d.closed = true
	return nil
}

func NewKeyManager(initialKey []byte) *KeyManager {
	keyCopy := make([]byte, len(initialKey))
	copy(keyCopy, initialKey)
	return &KeyManager{
		currentKey: keyCopy,
		oldKeys:    make(map[string][]byte),
		keyExpiry:  time.Now().Add(24 * time.Hour),
		maxOldKeys: 10,
	}
}

func (km *KeyManager) RotateKey() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	oldKeyHex := hex.EncodeToString(km.currentKey)
	oldKeyCopy := make([]byte, len(km.currentKey))
	copy(oldKeyCopy, km.currentKey)
	km.oldKeys[oldKeyHex] = oldKeyCopy

	if len(km.oldKeys) > km.maxOldKeys {
		for k := range km.oldKeys {
			delete(km.oldKeys, k)
			break
		}
	}

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return err
	}
	km.currentKey = newKey
	km.keyExpiry = time.Now().Add(24 * time.Hour)
	return nil
}

func (km *KeyManager) GetCurrentKey() []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()
	c := make([]byte, len(km.currentKey))
	copy(c, km.currentKey)
	return c
}

func (km *KeyManager) GetKeyByID(keyID string) []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()

	h := sha256.Sum256(km.currentKey)
	currentID := hex.EncodeToString(h[:8])
	if keyID == currentID {
		c := make([]byte, len(km.currentKey))
		copy(c, km.currentKey)
		return c
	}
	if oldKey, ok := km.oldKeys[keyID]; ok {
		c := make([]byte, len(oldKey))
		copy(c, oldKey)
		return c
	}
	return nil
}

func (km *KeyManager) IsExpired() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return time.Now().After(km.keyExpiry)
}

func (km *KeyManager) CleanupOldKeys() {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.oldKeys = make(map[string][]byte)
}

func NewDeENCWriter(deenc *DeENC, writer io.Writer) *DeENCWriter {
	return &DeENCWriter{
		deenc:  deenc,
		writer: writer,
		buffer: make([]byte, 0, 4096),
	}
}

func (w *DeENCWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, errors.New("writer is closed")
	}
	w.buffer = append(w.buffer, p...)

	const chunkSize = 1024
	for len(w.buffer) >= chunkSize {
		encrypted, err := w.deenc.Encrypt(w.buffer[:chunkSize])
		if err != nil {
			return 0, err
		}
		for _, word := range encrypted {
			if _, err := fmt.Fprintf(w.writer, "%s\n", word); err != nil {
				return 0, err
			}
		}
		w.buffer = w.buffer[chunkSize:]
		w.position += chunkSize
	}
	return len(p), nil
}

func (w *DeENCWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	if len(w.buffer) > 0 {
		encrypted, err := w.deenc.Encrypt(w.buffer)
		if err != nil {
			return err
		}
		for _, word := range encrypted {
			fmt.Fprintf(w.writer, "%s\n", word)
		}
	}
	w.closed = true
	return nil
}

func NewDeENCReader(deenc *DeENC, reader io.Reader) *DeENCReader {
	return &DeENCReader{
		deenc:  deenc,
		reader: reader,
	}
}

func (r *DeENCReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}

	buf := make([]byte, 1)
	var words []string

	for {
		n, err := r.reader.Read(buf)
		if n > 0 {
			ch := buf[0]
			if ch == '\n' {
				line := strings.TrimSpace(r.lineBuf.String())
				r.lineBuf.Reset()
				if line != "" {
					words = append(words, line)
					decoded, decErr := r.deenc.Decrypt(words)
					if decErr != nil {
						return 0, decErr
					}
					r.pending = append(r.pending, decoded...)
					words = words[:0]

					nc := copy(p, r.pending)
					r.pending = r.pending[nc:]
					return nc, nil
				}
			} else {
				r.lineBuf.WriteByte(ch)
			}
		}
		if err != nil {
			if r.lineBuf.Len() > 0 {
				line := strings.TrimSpace(r.lineBuf.String())
				r.lineBuf.Reset()
				if line != "" {
					words = append(words, line)
				}
			}
			if len(words) > 0 {
				decoded, decErr := r.deenc.Decrypt(words)
				if decErr != nil {
					return 0, decErr
				}
				r.pending = append(r.pending, decoded...)
			}
			if len(r.pending) > 0 {
				nc := copy(p, r.pending)
				r.pending = r.pending[nc:]
				return nc, nil
			}
			return 0, err
		}
	}
}

func constantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
