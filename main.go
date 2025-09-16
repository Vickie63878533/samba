package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultOpenAIURL = "https://api.sambanova.ai"
	contentTypeText  = "text/plain; charset=utf-8"
)

var (
	targetURL   *url.URL
	keyList     *KeyList
	CHECK_MODEL string // 全局变量用于/check端点
)

// KeyUsageInfo 存储每个 key 的使用情况
type KeyUsageInfo struct {
	Timestamps []time.Time // 记录每次使用的时间戳
}

// KeyList manages a list of API keys.
type KeyList struct {
	mu         sync.RWMutex
	keys       []string
	models     []string
	keyUsage   map[string]*KeyUsageInfo // 跟踪每个 key 的使用情况
	keyIndex   int
	modelIndex int
	rphLimit   int // 每小时请求限制 (Requests Per Hour)
	rpdLimit   int // 每日请求限制 (Requests Per Day)
}

func loadValueFromEnv(name string) (*[]string, error) {
	tokenListStr := os.Getenv(name)
	if tokenListStr == "" {
		return nil, fmt.Errorf("environment variable %s not set or empty", name)
	}

	keys := strings.Split(tokenListStr, ",")
	if len(keys) == 0 || (len(keys) == 1 && keys[0] == "") {
		return nil, fmt.Errorf("no keys found in environment variable %s after splitting", name)
	}

	// Trim whitespace from each key
	cleanedKeys := make([]string, 0, len(keys))
	for _, k := range keys {
		trimmedKey := strings.TrimSpace(k)
		if trimmedKey != "" {
			cleanedKeys = append(cleanedKeys, trimmedKey)
		}
	}

	if len(cleanedKeys) == 0 {
		return nil, fmt.Errorf("no valid keys found in environment variable %s after trimming", name)
	}

	return &cleanedKeys, nil
}

// loadIntFromEnv 从环境变量加载一个整数值，如果未设置则使用默认值
func loadIntFromEnv(name string, defaultValue int) int {
	valueStr := os.Getenv(name)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

// NewKeyListFromEnv creates a new KeyList from the TOKEN_LIST environment variable.
// The environment variable should contain a comma-separated list of keys.
func NewKeyListFromEnv(keyName string, modelName string) (*KeyList, error) {
	keys, err := loadValueFromEnv(keyName)
	if err != nil {
		return nil, err
	}
	models, err := loadValueFromEnv(modelName)
	if err != nil {
		return nil, err
	}
	rphLimit := loadIntFromEnv("RPH_LIMIT", 40)
	rpdLimit := loadIntFromEnv("RPD_LIMIT", 400)

	// 初始化每个 key 的使用情况
	keyUsage := make(map[string]*KeyUsageInfo)
	for _, key := range *keys {
		keyUsage[key] = &KeyUsageInfo{
			Timestamps: make([]time.Time, 0),
		}
	}

	return &KeyList{
		keys:       *keys,
		models:     *models,
		keyUsage:   keyUsage,
		keyIndex:   0,
		modelIndex: 0,
		rphLimit:   rphLimit,
		rpdLimit:   rpdLimit,
	}, nil
}

// GetRandomKeyAndModel returns a random key from the list.
// It returns an empty string and an error if no keys are available.
func (kl *KeyList) GetRandomKeyAndModel() (string, string, error) {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if len(kl.keys) == 0 {
		return "", "", fmt.Errorf("no keys available")
	}

	if len(kl.models) == 0 {
		return "", "", fmt.Errorf("no models available")
	}

	now := time.Now()
	for i := 0; i < len(kl.keys); i++ {
		// 轮换 key 和 model 的逻辑
		if kl.modelIndex >= len(kl.models) {
			kl.modelIndex = 0
			kl.keyIndex = (kl.keyIndex + 1) % len(kl.keys)
		}

		key := kl.keys[kl.keyIndex]
		model := kl.models[kl.modelIndex]

		// 检查此 key 是否已达到速率限制
		if kl.isRateLimited(key, now) {
			kl.keyIndex = (kl.keyIndex + 1) % len(kl.keys)
			kl.modelIndex = 0 // 重置 model 索引，确保下一个 key 从第一个 model 开始
			continue          // 继续循环，检查下一个 key
		}

		// 如果 key 可用，则记录本次使用并返回
		kl.recordUsage(key, now)
		kl.modelIndex++ // 为下一次调用准备

		return key, model, nil
	}

	// 如果循环了所有 key 都没有找到可用的，则返回错误
	return "", "", fmt.Errorf("all keys are currently rate-limited")
}

// isRateLimited 检查指定的 key 是否已达到 RPH 或 RPD 限制
func (kl *KeyList) isRateLimited(key string, now time.Time) bool {
	// 如果限制为0或负数，则认为没有限制
	if kl.rphLimit <= 0 && kl.rpdLimit <= 0 {
		return false
	}

	usage := kl.keyUsage[key]
	oneHourAgo := now.Add(-1 * time.Hour)
	oneDayAgo := now.Add(-24 * time.Hour)

	requestsInHour := 0
	requestsInDay := 0

	// 倒序遍历时间戳效率更高，因为我们关心的是最近的记录
	for i := len(usage.Timestamps) - 1; i >= 0; i-- {
		ts := usage.Timestamps[i]
		if ts.After(oneDayAgo) {
			requestsInDay++
			if ts.After(oneHourAgo) {
				requestsInHour++
			}
		} else {
			// 由于时间戳是按顺序添加的，一旦遇到比一天前还早的记录，就可以停止遍历
			break
		}
	}

	if kl.rpdLimit > 0 && requestsInDay >= kl.rpdLimit {
		return true // 达到每日限制
	}
	if kl.rphLimit > 0 && requestsInHour >= kl.rphLimit {
		return true // 达到每小时限制
	}

	return false
}

// recordUsage 记录一次 key 的使用，并清理过期的时间戳
func (kl *KeyList) recordUsage(key string, now time.Time) {
	usage := kl.keyUsage[key]

	// 清理超过24小时的旧记录
	oneDayAgo := now.Add(-24 * time.Hour)
	validTimestamps := make([]time.Time, 0, len(usage.Timestamps)+1)
	for _, ts := range usage.Timestamps {
		if ts.After(oneDayAgo) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	// 添加当前时间戳
	usage.Timestamps = append(validTimestamps, now)
}

// RemoveKey removes a specific key from the list.
// It returns true if the key was found and removed, false otherwise.
func (kl *KeyList) RemoveKey(keyToRemove string) bool {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	initialLen := len(kl.keys)
	updatedKeys := make([]string, 0, initialLen)
	found := false

	for _, key := range kl.keys {
		if key == keyToRemove {
			found = true
			// Skip adding this key to updatedKeys
			log.Printf("Removing unavailable key: %s", keyToRemove)
			continue
		}
		updatedKeys = append(updatedKeys, key)
	}

	kl.keys = updatedKeys
	return found
}

// GetAllKeys returns a copy of all keys.
func (kl *KeyList) GetAllKeys() []string {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	keysCopy := make([]string, len(kl.keys))
	copy(keysCopy, kl.keys)
	return keysCopy
}

// AvailableKeys returns a comma-separated string of currently available keys.
func (kl *KeyList) AvailableKeys() string {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return strings.Join(kl.keys, ",")
}

// RandomlyPrintAvailableKeys prints all available keys with a 1/20 chance.
// Keys are printed as a comma-separated string.
func (kl *KeyList) RandomlyPrintAvailableKeys() {
	// rand.Intn(20) generates a number between 0 and 19.
	// So, a 1/20 chance means checking if the result is, for example, 0.
	if rand.Intn(20) == 0 {
		kl.mu.RLock()
		defer kl.mu.RUnlock()
		if len(kl.keys) > 0 {
			fmt.Printf("Available keys (randomly printed): %s\n", strings.Join(kl.keys, ","))
		} else {
			fmt.Println("No keys available (randomly printed).")
		}
	}
}

// init 在 main 函数之前执行，用于初始化配置
func init() {
	// 从环境变量获取目标 URL
	openaiURLStr := os.Getenv("OPENAI_URL")
	if openaiURLStr == "" {
		openaiURLStr = defaultOpenAIURL
		log.Printf("OPENAI_URL not set, using default: %s", defaultOpenAIURL)
	}

	var err error
	targetURL, err = url.Parse(openaiURLStr)
	if err != nil {
		log.Fatalf("Error parsing OPENAI_URL '%s': %v", openaiURLStr, err)
	}
	log.Printf("Forwarding requests to: %s", targetURL.String())

	keyList, err = NewKeyListFromEnv("TOKEN_LIST", "MODEL_LIST")
	if err != nil {
		log.Fatalf("Failed to initialize key list: %v", err)
	}
	CHECK_MODEL = "Meta-Llama-3.1-8B-Instruct"
}

// handleRequest 是主要的 HTTP 请求处理器
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// 获取请求路径
	path := r.URL.Path

	// 检查是否为根路径或空路径的直接访问
	if path == "/" || path == "" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// 检查是否为 /check 路径
	if path == "/check" {
		handleCheck(w, r)
		return
	}

	// 原有的 /v1 路径处理逻辑
	if !strings.HasPrefix(path, "/v1") {
		http.NotFound(w, r)
		return
	}

	// 选择 API 密钥
	apiKey, model, err := keyList.GetRandomKeyAndModel()
	if err != nil {
		log.Printf("API key selection error: %v", err)
		http.Error(w, "请提供有效的 API 密钥 (Please provide a valid API key in Authorization header or configure TOKEN_LIST)", http.StatusForbidden)
		w.Header().Set("Content-Type", contentTypeText)
		return
	}
	log.Printf("Using API key : %s", apiKey)

	keyList.RandomlyPrintAvailableKeys()

	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// 自定义 Director 函数来修改请求
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req) // 执行默认的 Director 逻辑 (如设置 X-Forwarded-For 等)

		// 设置目标请求的 URL scheme, host 和 path
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.URL.Path = targetURL.Path + path // 使用原始请求的路径拼接到目标域名后

		// 修改 Host 头部
		req.Host = targetURL.Host

		// 设置 Authorization 头部
		req.Header.Set("Authorization", "Bearer "+apiKey)

		req.Header.Del("Cf-Connecting-Ip")
		req.Header.Del("Cf-Ipcountry")
		req.Header.Del("Cf-Visitor")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Real-Ip")
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Port")
		req.Header.Del("X-Stainless-Arch")
		req.Header.Del("X-Stainless-Package-Version")
		req.Header.Del("X-Direct-Url")
		req.Header.Del("X-Middleware-Subrequest")
		req.Header.Del("X-Stainless-Runtime")
		req.Header.Del("X-Stainless-Lang")
		req.Header.Set("User-Agent", "PostmanRuntime/7.43.2")

		// --- 开始修改请求 body 以注入 model ---
		if req.Body != nil {
			bodyBytes, readErr := io.ReadAll(req.Body)
			if readErr != nil {
				log.Printf("Error reading request body: %v. Forwarding without model injection.", readErr)
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			} else {
				req.Body.Close()
				var data map[string]interface{}
				if unmarshalErr := json.Unmarshal(bodyBytes, &data); unmarshalErr == nil {
					data["model"] = model
					modifiedBodyBytes, marshalErr := json.Marshal(data)
					if marshalErr == nil {
						req.Body = io.NopCloser(bytes.NewBuffer(modifiedBodyBytes))
						req.ContentLength = int64(len(modifiedBodyBytes))
						req.GetBody = func() (io.ReadCloser, error) {
							return io.NopCloser(bytes.NewBuffer(modifiedBodyBytes)), nil
						}
						log.Printf("Successfully injected model '%s' into request body.", model)
					} else {
						log.Printf("Error marshalling modified body: %v. Forwarding original body.", marshalErr)
						req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
						req.ContentLength = int64(len(bodyBytes))
						req.GetBody = func() (io.ReadCloser, error) {
							return io.NopCloser(bytes.NewBuffer(bodyBytes)), nil
						}
					}
				} else {
					log.Printf("Error unmarshalling request body: %v. Forwarding original body.", unmarshalErr)
					req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
					req.ContentLength = int64(len(bodyBytes))
					req.GetBody = func() (io.ReadCloser, error) {
						return io.NopCloser(bytes.NewBuffer(bodyBytes)), nil
					}
				}
			}
		} else if req.Body != nil {
			log.Printf("Request body present but Content-Type is not application/json ('%s'). Model not injected.", req.Header.Get("Content-Type"))
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request == nil {
			log.Println("WARN: ModifyResponse: resp.Request is nil. Cannot check for API key context.")
			return nil
		}

		if resp.StatusCode != http.StatusOK {
			// 1. 读取响应体以获取错误信息
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("ERROR: Received status %d for key '%s', but failed to read response body: %v", resp.StatusCode, apiKey, err)
				resp.Body.Close() // 即使读取失败，也要尝试关闭
				return err        // 返回一个错误，因为响应修改过程失败了
			}
			// 2. 读取后必须关闭原始的 Body
			_ = resp.Body.Close()

			// 3. 将读取的内容重新包装成一个新的 ReadCloser 放回 Body 中
			//    这样，调用这个代理的客户端才能接收到原始的错误响应
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// 4. 记录完整的错误日志
			log.Printf(
				"ERROR: Upstream returned non-200 status. Key: '%s', Status: %d, Body: %s",
				apiKey,
				resp.StatusCode,
				string(bodyBytes),
			)
		}
		
		if resp.StatusCode == http.StatusForbidden { // 403
			log.Printf("INFO: ModifyResponse: Upstream returned 403 for key: '%s'. Attempting to remove it.", apiKey)
			// keyList.RemoveKey(apiKey)
			return nil
		}
		if resp.StatusCode == http.StatusUnprocessableEntity { // 422
			log.Printf("INFO: ModifyResponse: Upstream returned 422 for key: '%s'. Attempting to remove it.", apiKey)
			keyList.RemoveKey(apiKey)
			return nil
		}
		return nil
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(rw, "Error forwarding request.", http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}

// handleCheck 检查所有 key 的状态
func handleCheck(w http.ResponseWriter, r *http.Request) {
	if CHECK_MODEL == "" {
		http.Error(w, "CHECK_MODEL environment variable is not set.", http.StatusInternalServerError)
		return
	}

	allKeys := keyList.GetAllKeys()
	var aliveKeys []string
	var failedKeys []string

	var wg sync.WaitGroup
	var mu sync.Mutex

	client := &http.Client{
		Timeout: 30 * time.Second, // 设置一个合理的超时
	}

	checkURL := targetURL.String() + "/v1/chat/completions"

	for _, key := range allKeys {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()

			// 构造请求体
			requestBody, err := json.Marshal(map[string]interface{}{
				"model": CHECK_MODEL,
				"messages": []map[string]string{
					{"role": "user", "content": "Hi"},
				},
				"max_tokens": 5,
			})
			if err != nil {
				log.Printf("Error creating request body for key %s: %v", key, err)
				return
			}

			req, err := http.NewRequest("POST", checkURL, bytes.NewBuffer(requestBody))
			if err != nil {
				log.Printf("Error creating request for key %s: %v", key, err)
				return
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+key)

			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				failedKeys = append(failedKeys, fmt.Sprintf("%s request_error %v", key, err))
				mu.Unlock()
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			if resp.StatusCode == http.StatusOK {
				aliveKeys = append(aliveKeys, key)
			} else {
				bodyBytes, _ := io.ReadAll(resp.Body)
				failedKeys = append(failedKeys, fmt.Sprintf("%s %d %s", key, resp.StatusCode, string(bodyBytes)))
			}
			mu.Unlock()

		}(key)
		time.Sleep(100 * time.Millisecond)
	}

	wg.Wait()

	var responseBuilder strings.Builder
	responseBuilder.WriteString("alive:\n")
	for _, key := range aliveKeys {
		responseBuilder.WriteString(key)
		responseBuilder.WriteString("\n")
	}

	responseBuilder.WriteString("\nfail:\n")
	for _, failInfo := range failedKeys {
		responseBuilder.WriteString(failInfo)
		responseBuilder.WriteString("\n")
	}

	w.Header().Set("Content-Type", contentTypeText)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseBuilder.String()))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // 默认端口
		log.Printf("PORT environment variable not set, using default %s", port)
	}

	http.HandleFunc("/", handleRequest)    // handleRequest 现在会路由到 /check
	http.HandleFunc("/check", handleCheck) // 直接为 /check 注册处理器

	server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 300 * time.Second, // 对于流式响应，可能需要更长或无超时
		IdleTimeout:  600 * time.Second,
	}

	log.Printf("Starting server on port %s...", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v\n", port, err)
	}
}
