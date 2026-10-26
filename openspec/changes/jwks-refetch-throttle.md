---
title: JWKS 重抓加上頻率上限，驗不過的權杖不再觸發重抓
type: fix
status: implemented
created: 2026-10-26
---

# JWKS 重抓加上頻率上限

## 問題

`middleware/auth/jwt.go` 的 `RequireJWT` 遇到任何驗證失敗（過期、亂填、簽章錯）都會清掉金鑰快取、向 Logto 重抓 JWKS 再驗一次。未登入的人只要帶一個假的 Bearer 權杖，每個請求就讓服務向 Logto 發一次請求。Logto 若因此限制來源，正常使用者的權杖也會驗不過。

另外三個問題：

- 金鑰編號不在快取裡時，`getKey` 每次都直接重抓，同樣沒有上限。
- Logto 回非 200（例如 429）時，錯誤內容照樣被當成 JWKS 解析，得到空清單後把手上的好金鑰整批蓋掉。
- 重試那段只接受 RSA，Logto Cloud 發的是 ES384，換金鑰時這段重試本來就沒作用。

## 變更內容

1. 拿掉 `RequireJWT` 裡「失敗就清快取再驗一次」那段。不認得的金鑰編號仍由 `getKey` 重抓，換金鑰照樣能接上。
2. `fetchJWKS` 記錄最後一次嘗試時間，一分鐘內最多向 Logto 抓一次。
3. 抓取失敗、回應不是 200、或清單裡沒有可用金鑰時，不覆蓋快取，繼續用手上已有的金鑰。
4. 新增 `middleware/auth/jwt_test.go`，用本機假 Logto（ES384）驗證：合法權杖通過；50 個假權杖加 50 個未知金鑰編號只抓一次 JWKS；快取過期且 Logto 回 429 時，手上的金鑰仍能驗過。

## 影響範圍

| 對象 | 影響 |
| --- | --- |
| dashai-go | 升級到新 tag 後，`/shukuyo/user/*` 的驗證行為改變如上 |
| 對外介面 | `RequireJWT`、`GetUserID` 簽名不變 |

## UI 規格

無。

## 測試計畫

1. `go test ./middleware/auth/` 三個案例全過；同一組測試套在舊邏輯上，抓取次數 51 次、Logto 故障時回 401，兩案失敗。
2. `go build ./...`、`go vet ./...` 通過。
3. dashai-go 升級後本機建置與測試通過，推送後確認 Render 部署版本，Sentry 無新錯誤。
