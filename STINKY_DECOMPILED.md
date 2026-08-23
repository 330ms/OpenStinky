# Stinky.exe 反编译还原（应用层）

> 本文件是 `stinky` 命名空间自定义代码的反汇编还原结果。
> 函数名/变量名是**还原命名**（原二进制无符号表，仅 RTTI 类名可信）。
> 全量带注释反汇编见 `decompiled.txt`（455 个函数，3.9MB）。
> RVA 基址 0x140000000；已脱壳的映像见 `dump_stinky.bin`。

---

## 0. 应用层代码分布

应用层（`stinky` 命名空间，非 OpenSSL/STL/nlohmann）集中在 `.text` 的
**RVA 0x11E000 .. 0x1B6000** 区间（约 200KB / 200+ 个函数）。
之后 `0x1B6` 起为 OpenSSL 库代码（`OSSL_HPKE_*`、`tls_*`、`ossl_quic_*` 等）。

RTTI 类名（可信）：
```cpp
namespace stinky {
  namespace auth {
    class TransientHeartbeatError;   // 瞬时心跳错误
    class RejectedHeartbeatError;    // 心跳被拒
  }
  struct EphemeralTlsIdentity;       // 临时 TLS 身份（引用计数）
}
```

---

## 1. 核心模块清单（按 RVA）

| RVA | 大小 | 功能（由字符串交叉引用推断） |
|---|---|---|
| `0x12a240` | 2.5K | 授权码交互 UI（LICENSE / forget license / Checking license） |
| `0x12bfc0` | 25B | VMProtect 标记函数（`VMP_L01_ENFORCE_PROTECTED_RUNTIME`） |
| `0x12deb0` | 8.0K | **StinkyConfigure** 状态机 |
| `0x12c120` | 1.9K | 授权租约维持 / 目标运行时退出处理 |
| `0x1301d0` | 1.3K | activation / authorization / binding / device / heartbeat / hpke |
| `0x1306e0` | 3.5K | 本地授权服务（TLS listener） |
| `0x1322d0` | 745B | attestation broker |
| `0x132620` | 1.2K | **inject 派发 + 错误解析**（见 §2） |
| `0x133700` | 10K  | 授权策略校验 + recipe 模块绑定校验 |
| `0x137b00` | 2.3K | 运行时资质（target window 检测） |
| `0x13d540` | 1.1K | artifact SHA-256 校验 |
| `0x16a6e0` | 3.1K | **`/v3/activate` 请求构造**（见 §3） |
| `0x16dcf0` | 1.0K | 设备身份（`stinky-device-identity-v1`） |
| `0x172c90` | 5.0K | **`/v3/heartbeat` 请求/状态机** |
| `0x175810` | 1.0K | 设备身份生成 |
| `0x176410` | 3.7K | **HPKE 接收方密钥生成 / 私钥导出** |
| `0x177980` | 304B | 授权码格式校验 |
| `0x17bb20` | 4.1K | WinHTTP 认证传输（TLS policy / 连接 / 重定向） |
| `0x181080` | 989B | 设备身份 ACL（Windows 访问控制） |
| `0x181460` | 1.3K | 授权租约 expired/renewed |
| `0x18a8d0` | 2.5K | companion 文件 Authenticode 校验 |
| `0x18c3d0` | 164B | `crypto_secretbox_easy`（NaCl） |
| `0x18e8c0` | 4.1K | resident 配置派发 |
| `0x18f8d0` | 4.3K | **resident 模块加载** |
| `0x1927a0` | 1.6K | 本地捕获根证书 / `api.slinky.gg` |
| `0x193360` | 1.2K | TLS 吊销表（CRL）签发 |
| `0x19b9b0` | 6.6K | **attestation（证据）流程** |
| `0x1aabf0` | 13K  | 主流程（license → patched → slinky） |
| `0x1b0450` | 2.7K | **hosts 文件原子替换**（见 §4） |
| `0x1b1870` | 1.0K | 临时根证书安装 |
| `0x1b3ef0` | 3.8K | Slinky settings 目录准备 |

---

## 2. inject 模块（`0x132620`）—— 注入派发 + 错误解析

反汇编显示的是一段**字符串前缀匹配 → 错误码映射**的逻辑：
对 resident 模块返回的状态字符串，按片段匹配 `OpenProcess` / `allocation` /
`transfer` …，命中即映射为结构化错误 `inject.open_process` / `inject.allocate` /
`inject.write`（错误码 0x13/0x0F/0x0C…）。

还原伪代码（`std::string` 使用 SSO，长度 > 15 走堆）：
```cpp
enum InjectError { /* ... */ };

InjectError classify_resident_init_failure(const ResidentState& st) {
    if (st.runtime_component == nullptr)
        return { "resident_initialization_failed", 0x1e };

    std::string status = st.status_string();          // 内部 SSO 字符串
    const char* p = status.data();
    size_t      n = status.size();

    auto has_prefix = [&](const char* frag, size_t len) {
        if (n < len) return false;
        return prefix_compare(p, p + n, frag, len) == 0;   // 0x530530
    };

    if (has_prefix("OpenProcess", 11))  return { "inject.open_process",  0x13 };
    if (has_prefix("allocation",  10))  return { "inject.allocate",      0x0f };
    if (has_prefix("transfer",     8))  return { "inject.write",         0x0c };
    if (has_prefix("dispatch",     8))  return { "inject.dispatch",      ... };
    if (has_prefix("module",       6))  return { "inject.module_resolution", ... };
    // ...
    return { "inject.config_rejected", ... };
}
```
> 注：`0x530530` 是字符串前缀比较；函数先判断 `n` 是否达到片段长度再比较，
> 是典型的"状态串 → 错误分类"模式。真正的注入动作（OpenProcess/WriteProcessMemory/
> CreateRemoteThread）在 `resident_initialization_failed` 字符串对应的上层，
> 此函数只负责把 resident 的失败状态归类。

---

## 3. `/v3/activate` 请求构造（`0x16a6e0`）

反汇编显示：函数接收多个字符串参数（license、device_id、launcher_sha256、
resident_sha256、target_sha256、stinky_build_id），先校验授权码格式（`0x177980`），
再生成 HPKE 接收方密钥（`0x176410`），然后构造 JSON 并加密。

还原伪代码：
```cpp
ActivateRequest build_activate_request(
    const License& license,
    const DeviceIdentity& device,
    const std::string& launcher_sha256,
    const std::string& resident_sha256,
    const std::string& target_sha256,
    const std::string& build_id)
{
    if (!validate_license_format(license))           // 0x177980
        throw invalid_license_format;

    auto hpke = generate_hpke_recipient_key(         // 0x176410
        device, launcher_sha256, resident_sha256, target_sha256, build_id);

    nlohmann::json body = {
        { "device_id",         device.id() },
        { "license",           license.text() },
        { "launcher_sha256",   launcher_sha256 },
        { "resident_sha256",   resident_sha256 },
        { "target_sha256",     target_sha256 },
        { "stinky_build_id",   build_id },
    };
    return hpke_seal("/v3/activate", body);          // HPKE 封装后 POST
}
```
对应端点与字段在字符串目录中均有确证（`/v3/activate`、`device_id`、
`launcher_sha256`、`resident_sha256`、`target_sha256`、`stinky_build_id`）。

---

## 4. hosts 文件原子替换（`0x1b0450`）

反汇编包含一个 `0xcccccccd` 魔数的除法/取模循环 —— 这是 **itoa（整数转十进制）**
的经典常数，用于把端口/IP 数值转字符串拼进 hosts 内容。

还原伪代码：
```cpp
int rewrite_hosts_file(const std::string& hosts_path, const HostsEntry& entry) {
    // 1. 打开 hosts 路径（0x1b2990）
    auto fd = open_path(hosts_path);
    int  attrs = get_file_attributes(fd);            // 0x16c5e74
    if (attrs == -1) return "hosts_attributes_unavailable";
    if (attrs & FILE_ATTRIBUTE_READONLY)
        if (!clear_readonly(hosts_path))
            return "hosts_read_only_attribute_could_not_be_cleared";

    // 2. 拼 hosts 行： "<ip> <domain>"，端口转十进制（itoa 循环）
    std::string line = ip_string(entry.ip) + " " + entry.domain;   // 0x117110

    // 3. 写临时文件 + flush
    auto tmp = create_temp_file();                    // "hosts temporary file creation failed"
    write(tmp, line);                                 // "hosts temporary write failed"
    flush(tmp);                                       // "hosts temporary flush failed"

    // 4. 原子替换（MoveFileEx / ReplaceFile）
    if (!atomic_replace(tmp, hosts_path))             // "hosts atomic replacement failed"
        return "hosts_atomic_replacement_failed";

    restore_attributes(hosts_path);                   // "hosts attributes could not be restored"
    return 0;
}
```
> 这是典型的 DNS 劫持：把某个域名（很可能是 `api.stinky.top` 或目标站）指向
> 固定 IP，绕过 DNS 解析，配合本地 TLS 根证书做透明代理/中间人。

---

## 5. HPKE 认证与心跳（`0x176410` / `0x172c90`）

### 5.1 HPKE 接收方密钥生成（`0x176410`）
```cpp
HpkeRecipient generate_hpke_recipient_key(...) {
    auto key = OSSL_HPKE_keygen();                    // OpenSSL HPKE 密钥对
    if (!export_private(key))  throw "HPKE private key export failed";
    return { key.public_key, key.private_key };        // 私钥落地保存
}
```
关联字符串：`HPKE recipient key generation failed`、`HPKE private key export failed`、
`invalid activation binding`、`stinky-auth-v3-hpke`、`stinky-auth-v3-aad`。

### 5.2 `/v3/heartbeat` 状态机（`0x172c90`）
```cpp
HeartbeatResult do_heartbeat(HpkeContext& ctx, uint64_t counter) {
    // 状态校验
    if (state == INVALID)  throw invalid_heartbeat_state;
    if (state == PENDING)  throw invalid_pending_heartbeat_state;

    nlohmann::json req = { {"heartbeat_token",  token},
                           {"heartbeat_counter", counter},
                           {"lease_expires_at", ...} };
    auto resp = hpke_post("/v3/heartbeat", ctx, req);
    // 续租 / 过期分支
    if (resp.renewed)  return authorization_lease_renewed;
    if (resp.expired)  return authorization_lease_expired;
    ...
}
```
异常类 `stinky::auth::TransientHeartbeatError` / `RejectedHeartbeatError` 对应
"瞬时可重试"与"被拒绝"两类心跳失败。

---

## 6. 主流程（`0x1aabf0`，13KB）

字符串签名 `license | patched | slinky` 表明这是顶层的 license→patch→launch 编排。
结合状态日志（`stage:armed:launch Slinky` / `stage:patched:Slinky connected` /
`log:app:Slinky connected:good`），主流程大致为：

```cpp
int main(int argc, char** argv) {
    if (argc != 1) return unsupported_launch_arguments;

    // ① 授权
    auto license = load_or_prompt_license();          // 0x12a240 UI
    if (license.empty()) return license_not_recognized;

    // ② 设备身份 + 激活
    auto device = load_device_identity();             // 0x16dcf0 / 0x175810
    auto hpke   = build_hpke();
    auto ticket = activate(device, hpke, license);    // /v3/activate

    // ③ 拉取 recipe/manifest（注入指令）
    auto recipe = fetch_recipe(ticket);               // recipe_envelope/manifest
    verify_recipe_signature(recipe);                  // 防降级

    // ④ 篡改 hosts（DNS 劫持）
    rewrite_hosts_file(...);                          // 0x1b0450

    // ⑤ 注入 resident 到 target 进程
    inject_resident(recipe.target, recipe.resident);  // 0x132620 / 0x18f8d0

    // ⑥ 起本地 TLS 授权服务，向 Slinky 交接 runtime blob
    start_local_auth_service();                       // 0x1306e0
    handoff_runtime_to_slinky();                      // launch Slinky

    // ⑦ 心跳维持授权租约
    start_heartbeat_guard();                          // 0x184170
    for (;;) { heartbeat(); sleep(...); }             // /v3/heartbeat
}
```

---

## 7. 还原完整性说明

- **可重建**：全部 455 个应用函数已按 RVA 反汇编并注释字符串交叉引用
  （`decompiled.txt`），模块功能已按字符串目录 + RTTI 归类。
- **不可重建**：原始变量名、注释、`if/for` 结构、模板展开。上文伪代码中的
  C++ 结构是语义等价的还原，非逐字节原始源码。
- **库代码免还原**：OpenSSL、nlohmann JSON、MSVC STL 均为开源，直接引用对应版本
  （OpenSSL 3.x 静态库、nlohmann JSON v3.12.0）即可补齐工程。

---

## 8. 关键 C2 协议汇总

| 端点 | 用途 | 关键字段 |
|---|---|---|
| `POST https://api.stinky.top/v3/activate` | 激活/授权 | `device_id`, `license`, `launcher_sha256`, `resident_sha256`, `target_sha256`, `stinky_build_id` |
| `POST .../v3/heartbeat` | 心跳/续租 | `heartbeat_token`, `heartbeat_counter`, `lease_expires_at` |
| `POST .../v3/evidence` | 证据上报 | `evidence` |
| `GET .../healthz` | 健康检查 | — |
| `http://api.slinky.gg/slinky.crl` | TLS CRL 吊销 | — |

- 传输加密：HPKE（`stinky-auth-v3-hpke` 封装 + `stinky-auth-v3-aad` 附加数据）。
- 消息体：JSON（nlohmann）。
- 协议版本：`auth-2026-01/02`、`recipe-2026-01/02`。
- 授权码：`STK1-` 前缀；设备 ID：`stk-device-` 前缀。
