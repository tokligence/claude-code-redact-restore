[English](README.md) | [中文](README.zh-CN.md)

# Claude Secret Shield

> 在使用 Claude Code 时保护你的秘密凭据。自动检测、脱敏和还原 API key、token、密码及各类凭据。

## 功能特性

- **108 种秘密模式** -- 涵盖 OpenAI、Anthropic、AWS、GitHub、Stripe、Slack、数据库连接串、私钥、JWT 等 90+ 种类型
- **30 种文件类型拦截** -- `.env`、`credentials.json`、`id_rsa`、`.pem`、`.p12`、`.pfx` 等
- **自动还原** -- Claude 写入代码时，占位符自动还原为真实值
- **全局持久化映射** -- 同一个秘密值始终生成相同的占位符，跨会话一致
- **静态加密** -- 映射文件使用 Fernet（AES-128-CBC + HMAC-SHA256）加密存储
- **并行安全** -- 使用 `fcntl` 文件锁，支持多进程并发调用 hook
- **Bash 命令防护** -- 拦截 `cat .env` 等命令，脱敏命令输出中的秘密值
- **白名单** -- 通过 `.claude-redact-ignore` 跳过特定文件
- **二进制文件检测** -- 自动跳过非文本文件
- **原子写入** -- 使用 tempfile + rename，崩溃时不会损坏文件
- **崩溃恢复** -- 遗留的备份文件在下次调用时自动恢复
- **调试模式** -- 设置 `REDACT_DEBUG=1` 进行排查
- **45 个端到端测试** -- 全面的测试覆盖

## 工作原理

三层策略协同工作，保护你的秘密凭据：

```
                        你的代码文件
                              |
              +---------------+---------------+
              |               |               |
        第 1 层          第 2 层          第 3 层
        拦截文件         替换秘密         还原秘密
              |               |               |
              v               v               v
     危险文件直接      任意文件中的秘密    占位符在写入时
     拒绝读取         替换为无害的        自动还原为
     (.env, id_rsa,   {{PLACEHOLDER}}    真实值
      credentials...)
```

**第 1 层 -- 文件拦截（Block List）：** 某些文件不应该被读取。当 Claude 尝试读取 `.env`、`credentials.json`、`id_rsa` 或其他 30 种被拦截的文件类型时，hook 会直接拒绝读取。Claude 会收到一条错误信息，建议使用其他替代方式。

**第 2 层 -- 模式脱敏（Pattern Redaction）：** 对于其他所有文件，hook 会用 108 个正则表达式模式扫描内容。匹配到的秘密值会被替换为确定性的占位符，如 `{{OPENAI_KEY_a1b2c3d4}}`。Claude 只能看到占位符，永远看不到真实的 key。

**第 3 层 -- 自动还原（Auto Restore）：** 当 Claude 写入或编辑文件时，hook 会静默地将所有占位符替换回真实的秘密值。磁盘上的代码始终保持真实凭据。Claude 对此毫无感知。

## 快速开始

### 安装（一条命令）

```bash
git clone https://github.com/tokligence/claude-secret-shield.git /tmp/claude-redact-install && bash /tmp/claude-redact-install/install.sh && rm -rf /tmp/claude-redact-install
```

或者直接告诉 Claude Code：*"Install secret redaction from https://github.com/tokligence/claude-secret-shield"*

安装后请重启 Claude Code。

**前置条件：** Python 3.6+、`jq`

**推荐：** 安装 `cryptography` 以启用加密存储映射文件：

```bash
pip3 install cryptography
```

如果不安装，映射文件将以明文存储（已限制文件权限，但未加密）。

### 卸载

```bash
git clone https://github.com/tokligence/claude-secret-shield.git /tmp/claude-redact-install && bash /tmp/claude-redact-install/uninstall.sh && rm -rf /tmp/claude-redact-install
```

### 验证安装

1. 创建一个包含假秘密值的测试文件：
   ```bash
   echo 'OPENAI_API_KEY=sk-proj-EXAMPLE-NOT-A-REAL-KEY-12345678901234' > /tmp/test-secret.txt
   ```
2. 在 Claude Code 中输入："Read /tmp/test-secret.txt"
3. Claude 应该看到类似：`OPENAI_API_KEY={{OPENAI_KEY_a1b2c3d4}}`
4. 磁盘上的真实文件不会被修改（可以用 `cat /tmp/test-secret.txt` 验证）

## 架构设计

### Hook 生命周期

Hook 注册了三个 Claude Code 事件：

| Hook 事件 | 匹配的工具 | 用途 |
|------------|------------|------|
| `PreToolUse` | Read, Write, Edit, Bash | 在执行前拦截 |
| `PostToolUse` | Read, Write, Edit | 在执行后还原/清理 |
| `SessionEnd` | （全部） | 清理临时备份文件 |

### 请求流程

```
Claude Code 发起工具调用 (Read / Write / Edit / Bash)
        |
        v
  PreToolUse Hook
        |
  +-----+--------+--------+--------+
  |              |          |          |
  v              v          v          v
 Read          Write      Edit       Bash
  |              |          |          |
  v              v          v          v
 是否拦截?    加载        加载      是否拦截?
 (拒绝)       映射表      映射表    (拒绝命令)
  |              |          |          |
  v              v          v          v
 扫描秘密,    还原内容    重新脱敏   还原命令
 备份 +       中的占位    文件以     中的占位
 脱敏         符          检查新鲜度  符
  |              |          |          |
  v              v          v          v
 放行          放行 +     放行       放行 +
               更新                   更新
        |
        v
  Claude Code 执行工具
        |
        v
  PostToolUse Hook
        |
  +-----+--------+--------+
  |              |          |
  v              v          v
 Read          Write      Edit
 从备份        清理       还原编辑后
 还原原始      备份       文件中的
 文件                     占位符
        |
        v
  SessionEnd Hook（退出时）
        |
        v
  删除 /tmp 备份目录
  （映射文件保留）
```

### Read 流程（核心机制）

这是关键的设计洞察。Claude Code 内部会追踪哪些文件已经被"读取"过。如果一次 Read 被拒绝或重定向，Claude 之后就无法对该文件执行 Write 或 Edit（会报"file has not been read yet"错误）。解决方案如下：

1. `PreToolUse` 在 `Read(/path/to/config.py)` 时触发
2. Hook 读取文件，用 108 个模式扫描内容
3. Hook 将原始文件备份到 `/tmp/.claude-backup-{session}/`
4. Hook 用脱敏后的内容就地覆盖文件（保留时间戳）
5. Hook 返回 0（放行）-- Claude 正常读取到脱敏后的文件
6. Claude Code 将该文件路径标记为"已读取"（这是关键步骤）
7. `PostToolUse` 触发 -- hook 从备份中恢复原始文件

结果：Claude 看到的是脱敏内容，真实文件完好无损，Claude 后续可以正常 Write/Edit 该文件。

### 崩溃恢复

如果 Claude Code 在 PreToolUse（文件已被覆盖为脱敏内容）和 PostToolUse（原始文件已恢复）之间崩溃，备份文件会保留在磁盘上。在下次 hook 调用时，`restore_pending_backups()` 会在启动阶段运行，自动恢复所有遗留的备份。无需手动干预。

## 秘密模式

108 个模式按类别组织：

| 类别 | 数量 | 示例 |
|------|-----:|------|
| AI / ML 服务商 | 12 | OpenAI, Anthropic, Groq, Perplexity, Hugging Face, Replicate, DeepSeek, GCP/Gemini |
| 云服务商 | 9 | AWS（access key、secret、session token）、Azure、DigitalOcean、阿里云、腾讯云 |
| DevOps / CI-CD | 28 | GitHub（6 种 token 类型）、GitLab（5 种）、Bitbucket、npm、PyPI、Docker Hub、Terraform、Vault、Grafana、Pulumi、Linear |
| 支付处理商 | 10 | Stripe（4 种 key 类型）、Square、PayPal/Braintree、Adyen、Flutterwave |
| 通信服务 | 13 | Slack（4 种 token 类型）、Discord、Twilio、SendGrid、Mailchimp、Mailgun、Telegram、Teams |
| 数据库 / 存储 | 8 | PostgreSQL、MySQL、MongoDB、Redis（带密码的连接串）、PlanetScale、Contentful |
| 分析 / 监控 | 5 | New Relic、Sentry、Dynatrace |
| 认证服务商 | 2 | 1Password、Age encryption |
| 其他服务 | 16 | Shopify、HubSpot、Postman、JFrog、Duffel、Typeform、EasyPost 等 |
| Git 凭据 | 3 | GitHub/GitLab/通用 URL 中嵌入的 token |
| 私钥 / Token | 2 | PEM 私钥块、JWT token |
| 通用模式 | 3 | `api_key=...`、`password=...`、env 格式中的 base64 秘密值 |
| **合计** | **108** | |

## 安全范围

### 本工具是什么

这是一个 **Claude Code hook**，用于防止 Claude **看到**你的真实秘密凭据。当 Claude 读取你的文件时，它看到的是 `{{OPENAI_KEY_a1b2c3d4}}` 而不是真实的 API key。当 Claude 写入代码时，占位符会被静默地还原为真实值。

### 本工具能防护的威胁

| 威胁 | 是否防护？ | 方式 |
|------|-----------|------|
| Claude 在代码中看到你的 API key | 是 | 基于模式的脱敏（108 种模式） |
| Claude 读取 .env / credentials 文件 | 是 | 文件拦截（30 种文件类型） |
| Claude 在连接串中看到数据库密码 | 是 | 模式匹配（MongoDB、PostgreSQL、MySQL、Redis URL） |
| Claude 看到私钥（RSA、Ed25519 等） | 是 | PEM 头部检测 + 文件拦截 |
| 映射文件从磁盘被窃取 | 是 | Fernet 静态加密 |
| 同一个秘密值生成不同的占位符 | 是 | 基于 HMAC 的确定性映射 |

### 本工具无法防护的威胁

| 威胁 | 是否防护？ | 原因 |
|------|-----------|------|
| Claude 运行任意代码读取 .env | **否** | Bash 正则拦截是尽力而为，非万无一失 |
| Claude 使用 `python3 -c "open('.env').read()"` | **否** | 程序化读取文件的方式无穷无尽 |
| Bash 命令输出中打印的秘密值 | **部分** | 已知模式会被脱敏，但无法覆盖所有输出 |
| root 用户读取你的文件 | **否** | root 可以绕过所有文件权限 |
| hook 运行时的内存转储 | **否** | 脱敏过程中秘密值会短暂存在于 RAM 中 |
| 提示注入攻击让 Claude 泄露秘密值 | **否** | 这是应用层攻击，不是文件读取攻击 |
| 二进制文件中的秘密值（编译代码、图片） | **否** | 二进制文件会被跳过 |
| 未覆盖格式中的秘密值 | **否** | 只能检测内置的 108 种模式 + 自定义模式 |

### 结论

> **本工具让 Claude Code 更安全，但并非万无一失。** 它防止了最常见的秘密泄露方式（Claude 读取包含嵌入凭据的源文件）。它**无法**防止蓄意攻击者或被劫持的 Claude 通过其他途径获取秘密。请将其作为纵深防御策略的一环，配合使用正规的秘密管理方案（Vault、环境变量、短期 token）。

### 安全实现细节

- **基于 HMAC 的占位符** -- 确定性生成，没有密钥无法反推
- **Fernet 加密** -- 映射文件静态加密（AES-128-CBC + HMAC-SHA256）
- **密钥分离** -- HMAC 密钥用于生成占位符，派生密钥用于加密
- **文件权限** -- HMAC 密钥 0400，映射文件 0600
- **原子写入** + **fcntl 锁** -- 防崩溃、防并发

完整的加密细节和威胁模型，参见 [docs/SECURITY.md](docs/SECURITY.md)。

## 配置

### 白名单：`.claude-redact-ignore`

在项目根目录或 home 目录创建此文件，可跳过特定文件：

```
# 跳过测试 fixtures（包含假秘密值）
tests/fixtures/*

# 跳过特定配置文件
config/example.yaml
```

支持 glob 模式。以 `#` 开头的行为注释。

Hook 会检查两个位置：
1. `$CWD/.claude-redact-ignore`（项目级）
2. `~/.claude-redact-ignore`（全局级）

### 调试模式

设置 `REDACT_DEBUG=1` 可在 stderr 中查看详细日志：

```bash
REDACT_DEBUG=1 claude
```

会记录每次 hook 调用、模式匹配、备份/恢复操作以及映射文件的加载/保存活动。

### 自定义模式

在 `~/.claude/hooks/custom-patterns.py` 中添加你自己的模式（安装时不会覆盖此文件）：

```python
CUSTOM_SECRET_PATTERNS = [
    ("MY_INTERNAL_TOKEN", r"mycompany_tok_[A-Za-z0-9]{32,}"),
    ("INTERNAL_API_KEY", r"internal_[a-f0-9]{64}"),
]

CUSTOM_BLOCKED_FILES = [
    "my-secret-config.yaml",
    ".internal-credentials",
]
```

要开始使用，可以先复制示例文件：

```bash
cp ~/.claude/hooks/custom-patterns.example.py ~/.claude/hooks/custom-patterns.py
```

重新运行 `install.sh` 会更新上游模式，但不会影响你的自定义模式。

## 文件说明

### 安装的文件

```
~/.claude/
  hooks/
    redact-restore.py          # 主 hook 脚本
    patterns.py                # 108 种秘密模式（安装时更新）
    custom-patterns.py         # 你的自定义模式（安装时不会覆盖）
    custom-patterns.example.py # 自定义模式示例文件
  settings.json                # Hook 注册（PreToolUse + PostToolUse + SessionEnd）
```

### 运行时文件

```
~/.claude/
  .redact-hmac-key             # 32 字节主密钥（权限 0400，仅生成一次）
  .redact-mapping.json         # 加密的秘密值-占位符映射（权限 0600）

/tmp/
  .claude-backup-{session_id}/ # Read 操作时的临时文件备份（会话结束时删除）
```

### 文件被删除时的影响

| 文件 | 删除后的影响 |
|------|------------|
| `.redact-hmac-key` | 下次运行时自动生成新密钥。旧映射文件将无法读取。所有秘密值会获得新的占位符。不会丢失数据。 |
| `.redact-mapping.json` | 创建新的空映射。Claude 会为遇到的秘密值生成新的占位符。不会丢失数据。 |
| `/tmp/.claude-backup-*` | 仅在会话活跃时删除才有影响。崩溃恢复将无法恢复这些文件。 |

## 测试

运行完整测试套件：

```bash
python3 -m pytest test_hook.py -v
```

或者不使用 pytest：

```bash
python3 test_hook.py
```

45 个测试覆盖：

- 拦截列表执行（被拦截的文件、允许的文件）
- 脱敏正确性（重叠模式、Unicode、二进制文件、空文件）
- Hook 协议（畸形输入、缺失字段、未知工具）
- 文件操作（权限保留、修改时间保留、原子写入）
- Bash 命令拦截（`cat .env`、输入重定向）
- 占位符还原（Write、Edit、Bash 命令）
- 会话生命周期（清理、映射跨会话持久化）
- 白名单（`.claude-redact-ignore` 模式）
- 并行安全（多进程并发访问映射文件）
- 崩溃恢复（遗留备份恢复）
- 完整端到端流程（Read -> Edit -> Write 周期）
- 加密映射（Fernet 加密/解密往返测试）

## 性能

每次工具调用约 10-30ms。Hook 运行速度快，因为：

- 模式在 import 时一次性编译
- 映射文件通过文件锁加载/保存（无外部依赖）
- 二进制文件检测只读取前 8KB
- 未发现秘密值时提前退出

## 常见问题

**问：这对所有 Claude Code 工具都有效吗？**
答：是的。Read、Write、Edit 和 Bash 全部被拦截。其他工具不受影响，直接通过。

**问：如果 Claude 尝试在 Bash 中运行 `cat .env` 怎么办？**
答：Hook 会拦截读取被封锁文件的 Bash 命令（`cat`、`head`、`tail`、`less`、`more`、`bat`、`source` 以及输入重定向）。

**问：这会损坏我的文件吗？**
答：不会。Hook 使用原子写入（tempfile + rename），并在修改前备份每个文件。即使 Claude Code 在操作中途崩溃，崩溃恢复也会在下次调用时自动恢复原始文件。

**问：为什么不直接用 `.gitignore`？**
答：`.gitignore` 只是防止文件被提交到 git，但 Claude Code 仍然可以读取这些文件。本工具从根源上防止 Claude 看到文件中的秘密值。

**问：可以和其他 Claude Code hook 一起使用吗？**
答：可以。安装程序会合并到你现有的 `settings.json` 中，不会删除其他 hook。

**问：如果不安装 `cryptography` 包会怎样？**
答：映射文件将以明文 JSON 存储而非加密存储。文件权限仍然是受限的（0600），但有权访问你 home 目录的人可以读取内容。安装 `cryptography` 可以增加 Fernet 加密，实现纵深防御。

**问：占位符在不同机器上一样吗？**
答：不一样。占位符由你个人的 HMAC 密钥（`~/.claude/.redact-hmac-key`）派生，每台机器的密钥是唯一的。同一个秘密值在两台不同机器上会产生不同的占位符。这是有意为之的设计——即使有人看到占位符，没有你的密钥也无法推断出真实的秘密值。

**问：如何重置所有设置？**
答：删除密钥和映射文件，然后重启 Claude Code：
```bash
rm ~/.claude/.redact-hmac-key ~/.claude/.redact-mapping.json
```
下次调用时会自动生成新密钥。

## 许可证

Apache 2.0
