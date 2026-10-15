# go-common

Shared Go packages for the dashai service ecosystem (dashai-go, factory, nicegarden 等)。提供一致的 HTTP 回應格式、middleware 與 Modbus 工具，避免各服務重複實作。

AI-assisted development（本庫部分程式碼由 Claude 協助開發）。

## Import path

```
github.com/seikaikyo/go-common
```

要求 Go 1.26 以上。

```bash
go get github.com/seikaikyo/go-common
```

## 主要 package

### response

標準 JSON 回應信封，所有 Go 服務共用同一格式，前端看到一致的 shape。

成功：`{"success": true, "data": ...}`
失敗：`{"success": false, "error": "..."}`

```go
import "github.com/seikaikyo/go-common/response"

response.OK(w, data)                  // 200 success
response.OKPage(w, data, total, page) // 200 success + 分頁
response.Err(w, http.StatusNotFound, "not found")
```

### middleware

`net/http` 相容的 middleware。

| 函式 | 用途 |
|------|------|
| `CORS(origins []string)` | 限定來源的 CORS |
| `RateLimit(requestsPerMinute int)` | 每分鐘請求數限流 |
| `RequestID(next http.Handler)` | 為每個請求注入 request id |
| `SecurityHeaders(next http.Handler)` | 注入安全相關 HTTP header |

```go
import "github.com/seikaikyo/go-common/middleware"

r.Use(middleware.RequestID)
r.Use(middleware.SecurityHeaders)
r.Use(middleware.CORS([]string{"https://shukuyo.seikai.dev"}))
r.Use(middleware.RateLimit(60))
```

### middleware/auth

Logto JWT 驗證 middleware。Logto Cloud 以 ES384（ECDSA P-384）簽發 token，自架 Logto 用 RS256，本 package 的 JWKS parser 同時支援 ECDSA（P-256 / P-384 / P-521）與 RSA。

```go
import "github.com/seikaikyo/go-common/middleware/auth"

r.Use(auth.RequireJWT(auth.JWTConfig{
    LogtoEndpoint:    "https://crzbx3.logto.app",
    LogtoAPIResource: "https://api.example.com",
}))

// handler 內取得使用者 ID
userID := auth.GetUserID(r.Context())
```

### modbus

Modbus 暫存器掃描與型別推測，供 go-edge-gateway 的裝置掃描功能使用。

- `Scan(req ScanRequest) (*ScanResult, error)`：依設定掃描暫存器區段
- `Analyze(raws []RawRegister) []AnalyzedRegister`：分析掃描結果，推測數值範圍、是否動態、float32 配對與可能類別
- 輔助函式：`ReadBatch` / `BytesToUint16` / `Float32FromPair` / `ListSerialPorts`

## 授權

見 LICENSE。
