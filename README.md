# base64share

Cloudflare Worker 文本分享服务。分享文本与管理员账户配置保存在 R2；普通长路径返回文本的 Base64 编码。

## 路由

- `/`：Nginx 欢迎页
- `/admin`：管理员登录/首次注册页面
- `/dashboard`：登录后的文本与账户控制台
- `/dashboard/session-secret/rotate`：登录后主动轮换会话密钥（仅接受 POST）
- `/logout`：退出登录
- 其他路径：去掉开头 `/` 后，字符数大于 10 时返回 Base64；否则返回长度不足错误

查询字符串不参与路径长度计算。路径中的百分号编码会先解码，再按 Unicode 字符计数。

## R2 数据

- `content/current.txt`：用户设置的分享文本
- `auth/credentials.json`：用户名、密码盐和 PBKDF2 哈希（不保存明文密码）
- `auth/session-secret.txt`：用于签名登录 Cookie 的随机会话密钥

Worker 没有部署完成钩子。`auth/session-secret.txt` 会在部署后的第一次 `/admin` 请求中检查；不存在时自动生成 32 字节随机密钥，并原子写入 R2。

当 R2 中没有账户配置时，`/admin` 显示“注册”按钮。注册完成后该按钮自动隐藏，后端也会拒绝再次注册。登录后可在控制台修改用户名和密码，也可以主动轮换会话密钥；两种操作都会让其他旧会话失效，并保持当前浏览器继续登录。

## 本地运行

```powershell
npm install
npm run dev
```

本地 R2 数据由 Wrangler 自动保存在 `.wrangler/`

## 首次部署

创建 R2 存储桶（名称需与 `wrangler.jsonc` 一致）：

```powershell
npx wrangler r2 bucket create base64share-content
```

然后部署：

```powershell
npm run deploy
```

部署后访问 `/admin` 完成首次注册。不再需要设置 `ADMIN_USERNAME`、`ADMIN_PASSWORD` 或 `SESSION_SECRET`。

管理界面单次保存上限为 10 MiB（UTF-8 字节数）。公开读取使用流式 Base64 编码，不会一次性把 R2 文本对象读入内存。
