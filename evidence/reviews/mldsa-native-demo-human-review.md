# mldsa-native Demo 脫敏證據——人工審查文件

建立日期：2026-07-15

狀態：**擁有者已批准**

NIST ACVTS Demo 測試向量已全部通過，公開檔案樹的自動掃描也沒有發現任何問題。本文件記錄擁有者本人完成的審查與批准；自動化工具或 AI 助理沒有代替擁有者作出發布決定。

## 待審查檔案

| 檔案 | SHA-256 | 審查目的 |
| --- | --- | --- |
| `evidence/sanitized/mldsa-native-demo-session/evidence-summary.json` | `07c3097d69fabe9cf27916db4af5929397ed57aade1547b544acad05184dd066` | 檢查 Demo 聲明、限制、backend metadata 與測試涵蓋範圍 |
| `evidence/sanitized/mldsa-native-demo-session/source-hashes.json` | `20c3198deb073f914cdac849a5ce63dc3076d8930e00ab1d4ad8375d8ba43ed5` | 連結私下保存的證據，但不包含 ID、路徑或原始測試向量 |
| `evidence/sanitized/mldsa-native-demo-session/export-attestation.json` | `17d9cbf3974f58665a6baeac7cbd1ef2bfd8cc34ad8176848c9ef13927f749e2` | 檢查匯出政策、原始測試向量排除狀態與擁有者批准紀錄 |
| `evidence/sanitized/mldsa-native-demo-session/SHA256SUMS` | `68379b85a9a5594ed804689bd5df06ff01d87b5584f278419a5735e3aadf7ea4` | 驗證上述三個 JSON 檔案的完整性 |

輔助自動掃描證據：`evidence/reviews/mldsa-native-demo-automated-scan.json`（`a92721d2321ee578b152f43550399bb654101a5b265c00c3ab2e697b5fdf54ef`）。共掃描 4 個檔案，發現 0 個問題，結果為通過。

## 擁有者審查清單

- [x] 我已開啟並閱讀 `evidence/sanitized/mldsa-native-demo-session/` 內的全部四個檔案。
- [x] 文件使用「NIST ACVTS Demo」字樣，沒有暗示已取得 CAVP certificate 或 CMVP validation。
- [x] ML-DSA FIPS 204、三種 mode、三個 parameter set、12 個 test group 與 210 個 test case 的描述正確。
- [x] 文件只宣告 pure ML-DSA 與 external interface。
- [x] 文件不包含 test-session ID、vector-set ID、帳號身分、個人身分或本機路徑。
- [x] 文件不包含原始測試向量、secret key、共用憑證、JWT、TOTP、Authorization header 或 client 設定。
- [x] 我接受公開列出的 SHA-256，並以它們連結私下保存的證據。
- [x] 在脫敏證據目錄執行 `shasum -a 256 -c SHA256SUMS` 能成功通過。
- [x] 我批准未來公開發布這些確切雜湊值所對應的檔案。

## 批准紀錄

以下紀錄由擁有者的明確批准更新。`reviewed_tree_sha256` 保留擁有者實際審查時的原始證據樹雜湊；`approved_tree_sha256` 是將 attestation 更新為 approved 並重新產生 checksums 後的新證據樹雜湊。

```text
decision: approved
reviewer: JunMin765677
reviewed_at: 2026-07-24T08:24:26Z
reviewed_tree_sha256: 61fbff0946d57a8c26f4dde30e66b75290becc46f4dc3599c506535a0bfe9aed
approved_tree_sha256: 68379b85a9a5594ed804689bd5df06ff01d87b5584f278419a5735e3aadf7ea4
notes: 擁有者確認全部審查項目均正確；attestation 已更新並重新產生 SHA256SUMS。
```

批准後的 `export-attestation.json` 與 `SHA256SUMS` 已透過可追蹤步驟更新；公開發布時必須維持上述檔案與雜湊一致。
