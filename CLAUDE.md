# go-common

dashai 生態系 Go 服務共用的套件庫，沒有可執行檔、沒有部署。使用說明與範例見 `README.md`。

## 套件

| 路徑 | 內容 | 使用端 |
|------|------|--------|
| `response/` | 統一 JSON 回應格式 `{"success", "data" / "error"}` | dashai-go、go-edge-gateway、go-ot-security |
| `middleware/` | CORS、限流、request id、安全標頭 | dashai-go |
| `middleware/auth/` | Logto JWT 驗證，JWKS 同時接受 ECDSA（Logto Cloud 發 ES384）與 RSA | dashai-go |
| `modbus/` | Modbus 暫存器掃描與型別推測 | go-edge-gateway（`internal/scan`） |

## 版本與發布

- 使用端以 tag 引用（目前最新 v0.2.1）。改了對外的函式簽名或行為就打新 tag，使用端再 `go get github.com/seikaikyo/go-common@<tag>`
- go-edge-gateway 的 `go.mod` 有 `replace ... => ../go-common`，本機開發時直接吃這個資料夾的程式碼，不受 tag 影響
- 改動前先查使用端：`response` 的回應格式是使用端前端解析的依據，改欄位要同步改使用端

## 開發

- Go 版本照 `go.mod`（go 1.26.1，toolchain go1.26.7）
- 驗證：`go build ./...`、`go vet ./...`。目前沒有測試檔
- 這是公開 repo，不放本機路徑、帳號、金鑰；README 的 Logto 網址是公開的租戶端點
