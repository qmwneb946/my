# My User Center (用户中心)
这是一个基于 Cloudflare Worker 构建的全功能用户中心和身份认证服务项目。它提供用户注册、登录、账户管理、OAuth 2.0/OIDC 服务、API 密钥管理、用户间私信以及管理员后台等功能。
## 主要功能
* **用户认证与管理**:
    * 支持邮箱/用户名和密码注册登录。
    * 安全的密码存储（哈希处理）。
    * 会话管理。
    * 两步验证 (2FA) 基于 TOTP。
    * 用户可修改个人资料（用户名、手机号）和密码。
* **OAuth 2.0 / OpenID Connect (OIDC) 服务**:
    * 作为身份提供方 (IdP)。
    * 支持 OAuth 2.0 授权码流程 (Authorization Code Flow)。
    * OIDC 发现端点 (`/.well-known/openid-configuration`, `/.well-known/jwks.json`)。
    * 允许用户注册和管理 OAuth 客户端应用 (Client Applications)。
    * 颁发 JWT 格式的 Access Token 和 ID Token (使用 RS256 签名)。
* **API 密钥管理**:
    * 允许用户为集成的外部服务（如“云剪贴板”、“Cloud PC”）生成 API 密钥。
* **私信功能**:
    * 注册用户之间可以进行一对一的私信交流。
    * 支持 Markdown 格式的消息内容。
    * 显示未读消息计数和对话列表。
* **管理员后台**:
    * 提供管理员界面管理用户和 OAuth 应用。
    * 查看用户列表和应用列表。
    * （可扩展）管理用户状态（激活/禁用）和应用状态（激活/暂停）。
* **前端用户界面 (UI)**:
    * 提供一个统一的 Web 界面供用户和管理员操作。
    * 主要模块包括：登录、注册、账户设置（个人信息、安全设置、API 密钥、我的应用、私信、API 使用示例）、管理员面板（用户管理、应用管理）。
    * 支持浅色/深色主题切换。
* **安全性增强**:
    * 集成 Cloudflare Turnstile 进行人机验证，防止恶意注册和登录。
## 技术栈
* **后端**: Cloudflare Workers (JavaScript, Node.js 运行时风格)
    * 路由和 API 逻辑
    * 数据存储: 预期使用 Cloudflare D1 (数据库) 和 Cloudflare KV (键值存储)
* **前端**: HTML, CSS, JavaScript
    * 纯客户端渲染，通过 API 与后端交互
* **开发与部署**: Wrangler CLI
## 项目结构
```
.
├── cdn/                    # 前端静态资源 (CSS, JS)
│   ├── css/
│   │   └── style.css       # 全局样式
│   └── js/
│       ├── main.js         # 前端主逻辑
│       ├── ui-admin.js     # 管理员面板 UI 逻辑
│       ├── ui-api-keys.js  # API 密钥 UI 逻辑
│       ├── ui-messaging.js # 私信 UI 逻辑
│       ├── ...
├── my/                     # Cloudflare Worker 源代码目录
│   ├── src/
│   │   ├── worker.js       # Worker 入口，路由
│   │   ├── api-handlers.js # API 端点处理
│   │   ├── oauth-server.js # OAuth/OIDC 服务逻辑
│   │   ├── jwt-utils.js    # JWT 工具
│   │   ├── html-ui.js      # HTML 界面生成
│   │   ├── helpers.js      # 通用辅助函数
│   │   └── turnstile-handler.js # Turnstile 验证
│   ├── package.json        # Node.js 项目配置
│   ├── package-lock.json   # 依赖锁定
│   └── wrangler.toml       # Wrangler 配置文件 (预期存在，用于部署)
└── README.md               # 本文件
```
## 环境配置 (预期)
部署此 Worker 需要在 Cloudflare 控制台或 `wrangler.toml` 文件中配置以下环境变量和绑定：
* **Bindings**:
    * `DB`: D1 数据库绑定，用于存储用户信息、会话、OAuth 客户端、授权码、私信等。
    * `cloudpc`: KV Namespace 绑定，用于 Cloud PC 密钥相关数据。
    * `CONVERSATION_DO`: Durable Object 绑定，用于处理实时消息。
    * `USER_PRESENCE_DO`: Durable Object 绑定，用于处理用户在线状态和通知。
* **Secrets / Environment Variables**:
    * `ADMIN_EMAILS`: 逗号分隔的管理员邮箱列表 (例如 "admin1@example.com,admin2@example.com")。
    * `TURNSTILE_SITE_KEY`: Cloudflare Turnstile 站点密钥 (用于前端)。
    * `TURNSTILE_SECRET_KEY`: Cloudflare Turnstile 秘密密钥 (用于后端验证)。
    * `PASTE_API_BEARER_TOKEN`: 外部云剪贴板服务的 Bearer Token (如果集成)。
    * `STRIPE_SECRET_KEY`: Stripe 的秘密密钥 (Base64 编码, 用于 GreenHub 激活码功能)。
    * `OAUTH_SIGNING_KEY_PRIVATE`: JWK 格式的 RSA 私钥，用于签署 JWT。
    * `OAUTH_SIGNING_KEY_PUBLIC`: JWK 格式的 RSA 公钥，用于 JWKS 端点。
    * `OAUTH_SIGNING_ALG`: JWT 签名算法 (默认为 "RS256")。
    * `ID_TOKEN_LIFETIME_SECONDS`: ID Token 的有效期秒数 (例如 "3600")。
    * `ACCESS_TOKEN_LIFETIME_SECONDS`: Access Token 的有效期秒数 (例如 "3600")。
    * `AUTHORIZATION_CODE_LIFETIME_SECONDS`: 授权码的有效期秒数 (例如 "600")。
    * `OAUTH_ISSUER_NAME`: OAuth 发行者名称 (用于 TOTP URI)。
    * `CDN_BASE_URL`: 前端静态资源 (CSS, JS) 的 CDN 基地址 (可选, 默认为 `https://cdn.qmwneb946.dpdns.org`)。
## 数据库结构 (预期)
根据代码推断，D1 数据库中可能包含以下表：
* `users`: 存储用户信息 (email, username, password_hash, phone_number, 2FA settings, `is_active` (boolean), `created_at` (timestamp))。
* `sessions`: 存储用户会话 (session_id, user_email, expires_at)。
* `oauth_clients`: 存储注册的 OAuth 客户端应用信息 (client_id, client_secret_hash, owner_email, redirect_uris, scopes, client_name, client_website, client_description, grant_types_allowed, created_at, `status` (e.g., 'active', 'suspended'))。
* `authorization_codes`: 存储 OAuth 授权码 (code, user_email, client_id, scopes, expires_at, used, nonce)。
* `refresh_tokens`: 存储 OAuth 刷新令牌 (token, user_email, client_id, scopes, expires_at, revoked, issued_at)。
* `conversations`: 存储私信对话元数据 (conversation_id, participant1_email, participant2_email, last_message_at, created_at)。
* `messages`: 存储私信消息内容 (message_id, conversation_id, sender_email, receiver_email, content, sent_at, is_read)。
## API 端点概览
### 用户认证与账户 API
* `POST /api/register`: 用户注册。
* `POST /api/login`: 用户登录。
* `POST /api/login/2fa-verify`: 2FA 登录验证。
* `POST /api/logout`: 用户登出。
* `GET /api/me`: 获取当前用户信息 (包含 `is_admin` 标志)。
* `POST /api/change-password`: 修改密码。
* `POST /api/update-profile`: 更新个人资料。
* `GET /api/2fa/generate-secret`: 生成 2FA 密钥。
* `POST /api/2fa/enable`: 启用 2FA。
* `POST /api/2fa/disable`: 禁用 2FA。
### API 密钥 API
* `POST /api/paste-keys`: 创建云剪贴板 API 密钥。
* `GET /api/cloudpc-key`: 获取 Cloud PC API 密钥。
* `POST /api/cloudpc-key`: 创建 Cloud PC API 密钥。
* `GET /api/greenhub-keys`: 获取 GreenHub 激活码。
### OAuth 客户端管理 API
* `POST /api/oauth/clients`: 注册新的 OAuth 客户端应用。
* `GET /api/oauth/clients`: 列出当前用户注册的 OAuth 应用。
* `PUT /api/oauth/clients/{client_id}`: 更新指定的 OAuth 应用信息。
* `DELETE /api/oauth/clients/{client_id}`: 删除指定的 OAuth 应用。
### 私信 API
* `POST /api/messages`: 发送私信 (或初始化对话)。
* `GET /api/conversations`: 获取当前用户的对话列表。
* `GET /api/messages/unread-count`: 获取当前用户的未读消息总数。
* (WebSocket) `/api/ws/user`: 用户状态和通知的 WebSocket 连接。
* (WebSocket) `/api/ws/conversation/{conversation_id}`: 特定对话的实时消息 WebSocket 连接。
### OAuth/OIDC 协议端点
* `GET /.well-known/openid-configuration`: OIDC 发现配置。
* `GET /.well-known/jwks.json`: IdP 的公钥集。
* `GET /oauth/authorize`: OAuth 授权端点 (用户同意页面)。
* `POST /oauth/authorize`: 处理用户同意提交。
* `POST /oauth/token`: OAuth 令牌端点 (交换授权码或刷新令牌获取新令牌)。
* `GET/POST /oauth/userinfo`: OIDC UserInfo 端点 (获取用户信息)。
### 管理员 API
* `GET /api/admin/users`: (管理员) 列出所有用户。
* `GET /api/admin/users/{user_email}`: (管理员) 获取特定用户信息。
* `PUT /api/admin/users/{user_email}`: (管理员) 更新特定用户信息 (例如，`is_active` 状态)。
* `GET /api/admin/oauth/clients`: (管理员) 列出所有 OAuth 应用。
* `GET /api/admin/oauth/clients/{client_id}`: (管理员) 获取特定 OAuth 应用信息。
* `PUT /api/admin/oauth/clients/{client_id}`: (管理员) 更新特定 OAuth 应用信息 (例如，`status`)。
### 其他
* `GET /api/config`: 获取前端配置，如 Turnstile Site Key。
* `GET /user/help`: API 使用示例和帮助页面。
## 如何运行和部署
1.  **安装 Wrangler**:
    ```bash
    npm install -g wrangler
    # 或者使用 npx wrangler
    ```
2.  **克隆仓库** (如果适用)。
3.  **配置 `wrangler.toml`**:
    * 设置 `name`, `main` (应为 `my/src/worker.js`), `compatibility_date`。
    * 配置 D1 数据库绑定、KV Namespace 绑定和 Durable Object 绑定。
    * 添加必要的环境变量 (Secrets)，包括 `ADMIN_EMAILS`。
4.  **安装依赖**:
    ```bash
    cd my # 进入包含 package.json 的目录
    npm install
    ```
5.  **本地开发**:
    ```bash
    npx wrangler dev
    ```
6.  **部署到 Cloudflare**:
    ```bash
    npx wrangler deploy
    ```
## 未来可能的改进
* 更细致的 OAuth Scope 管理和验证。
* 更完善的管理员后台用户和应用管理功能（例如：详细编辑、密码重置链接发送、更细致的状态管理）。
* 密码重置功能（用户自助）。
* 审计日志。
* 国际化支持。
* 邮件发送服务集成（用于验证、通知等）。
