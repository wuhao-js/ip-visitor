# 来路 LaiLu · 服务器来访IP监控

> 知道来路，才好应对。

解析 tcpdump 抓包文本输出，记录**入站方向**（别人访问本服务器）的 TCP/UDP/ICMP 流量，
通过带密码授权的 Web 页面实时查看、查询历史、统计来访客户端，并对异常行为告警、
支持针对指定 IP/端口按需抓包导出 pcap 深入分析。

## 两种使用方式

| 方式 | 适合场景 | 上手 |
|------|----------|------|
| **Windows 桌面版（exe）** | 办公电脑直接双击使用，免装 Node/免配环境 | 到 [Releases](https://github.com/wuhao-js/ip-visitor/releases) 下载：安装版 `lailu-setup-1.1.0.exe`（双击安装，开始菜单/桌面快捷方式）或绿色版 `lailu-win-x64-v1.1.0.zip`（解压双击 `lailu.exe`），均弹出独立应用窗口（免登录直接进入） |
| **服务器部署（Web 端）** | Linux 服务器长期监控入站流量，浏览器访问 | 源码部署，见下方「快速开始」与 systemd 部署示例 |

两种方式界面与功能完全一致（桌面版 = 内置内核 `lailu-core.exe` + Electron 独立窗口，**不依赖系统浏览器**，只监听 127.0.0.1 且免登录；服务器部署面向局域网/公网，需要登录）。

- 服务器部署需登录：初始账号 `admin / admin123`，登录后请在「账号」页修改密码（可再建 viewer 只读账号给同事看）；桌面版免登录
- 桌面版监控远程 Linux 服务器：页面「抓包诊断 → 管理主机」添加 SSH 主机即可（Windows 本机没有 tcpdump，远程抓包由服务器端执行）
- 桌面版数据目录：`%APPDATA%\来路`（config.json / data / 日志都在这里；拷贝该目录即迁移，卸载/升级不影响数据）

## 功能

- 流量页（实时+历史合一）：SSE 实时流入 + 24h 小时级趋势图、Top 来访客户端 / Top 访问端口；历史记录按来源 IP、目标端口、协议、时间范围筛选，分页浏览，点行即按该 IP 过滤
- 客户端统计：访问次数、持续时长、频率、访问端口（带服务名如 3306(MySQL)）、协议分布
- 行为判定：⚠ 疑似端口扫描（窗口内 distinct 端口数超阈值）、「新」首次来访 IP
- 告警：新客户端 / 疑似扫描入 SQLite + 页面红点实时推送 + webhook 通知
  （企业微信/钉钉群机器人格式），面板内可发测试告警验证链路
- 抓包诊断：按 IP / 端口 / 协议定向抓包 10-300 秒（本机或 **SSH 远程主机**，支持用户名+密码；
  IP 为双向匹配，类似 Wireshark 的 ip.addr，填服务器 IP 或客户端 IP 均可），
  远程主机在页面「管理主机」里直接增删改（写回 config.json 热生效，无需重启），
  可随时手动停止；页面内直接看**分析摘要**（自动诊断结论：扫描判定/RST 占比/Top 来源占比/TCP 握手时延/HTTP 识别，
  加上总量/速率/协议分布/TCP 标志/Top 端口/Top 来源/对话排行）、**会话流还原**（对话双向载荷按时间排列，
  类 Wireshark Follow Stream，请求/响应内容一眼看全）、报文列表与 hex 原始字节（Wireshark 式，TCP/UDP 载荷为
  JSON/可读文本时自动解析展示，二进制 hex 全量显示不截断），也可下载 pcap 深入分析
- 只记入站：默认内核级 `-Q in` 过滤；不支持时降级为「目标为本机 IP 且来源非本机」
- 登录与多用户（服务器部署需要；桌面版以 `--no-auth` 免登录运行）：账号+密码（scrypt 哈希存储），
  admin（管理员）/ viewer（只读）两种角色；首次启动自动创建 admin 账号（初始密码 admin123，或 config.password 指定值）；
  页面「账号」页改密码、管理员可增删用户
- 报文查看：Wireshark 式三栏（包列表 → 选中详情 → 载荷/原始字节），支持显示过滤
  （`ip:x port:x tcp syn has:payload text:关键字`，空格=并且；点摘要标签直接生成条件）
- 简单授权：未授权 API 返回 401，页面跳登录页；登录失败 5 次锁定 10 分钟
- SQLite 存储（WAL 模式），记录与告警按保留期自动清理（默认 7 天）

## 运行要求

- Node.js >= 22.13（使用内置 node:sqlite；低版本请 `npm i better-sqlite3` 自动回退）
- Linux 服务器需安装 tcpdump，且 Node 进程有抓包权限：
  - `sudo node src/server.js`，或
  - `sudo setcap cap_net_raw+eip $(which tcpdump)`（免 root，推荐），或
  - `sudo setcap cap_net_raw+eip $(readlink -f $(which node))`（给 node 授权，二选一）

## 快速开始

```bash
npm install
sudo node src/server.js          # 首次启动生成 config.json 并自动创建 admin 账号（初始密码 admin123）
# 浏览器访问 http://<服务器IP>:8321
```

Windows 本机无 tcpdump，用回放模式验证功能：

```bash
npm run start:replay             # 循环回放 test/samples/sample.log
```

## 配置（config.json）

| 字段 | 默认 | 说明 |
|------|------|------|
| port | 8321 | Web 监听端口 |
| password | 空（默认 admin123） | 初始 admin 密码（仅首次启动建号用；留空=公开默认值，请登录后在「账号」页修改） |
| secret | 自动生成 | 会话 Cookie 签名密钥，勿泄露 |
| dbFile | data/access.db | SQLite 文件路径 |
| iface | any | 抓包网卡（eth0/ens192 等） |
| retentionDays | 7 | 记录保留天数，0 为不清理 |
| tcpdumpBin | tcpdump | tcpdump 可执行文件路径 |
| sessionHours | 12 | 登录会话有效期 |
| localIps | [] | 服务器自身 IP（NAT/多网卡时补充，用于入站判定与回放） |
| scanPortsThreshold | 15 | 扫描判定：窗口内 distinct 端口数阈值 |
| scanWindowMin | 10 | 扫描判定时间窗口（分钟） |
| newIpHours | 24 | 多少小时内首次出现的 IP 标记为「新」 |
| webhookUrl | 空 | 企业微信/钉钉群机器人 webhook，空为不通知 |
| captureDir | data/captures | 按需抓包 pcap 存放目录 |
| remoteHosts | [] | 远程抓包主机：`[{"name":"web-1","host":"10.0.0.11","port":22,"user":"root","password":"xxx"}]`（密码与 keyFile 二选一） |

### 远程抓包说明

控制端通过 SSH（ssh2 库，支持**用户名+密码**或密钥）在目标机执行 `tcpdump -nn -U -w - '<BPF>'`，pcap 流式回传落盘：

1. 推荐：抓包诊断页点「管理主机」，在页面里直接添加（名称/IP/端口/用户/密码），保存即生效
2. 也可以直接编辑 config.json 的 remoteHosts（`password` 或 `keyFile` 二选一），改完重启
3. user 为 root 直接跑 tcpdump；非 root 需在目标机配置 `sudo tcpdump` 免密（`visudo` 加 `user ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump`）
4. 抓包诊断页「目标」下拉选择远程主机即可（默认「本机」始终可见）

## 命令行参数

```
node src/server.js [--config file] [--replay file] [--loop] [--port n] [--host addr] [--iface name] [--force-no-q] [--no-auth]
# --host 默认 0.0.0.0（局域网可访问）；桌面版内核用 --host 127.0.0.1 --no-auth（仅本机访问 + 免登录）
```

## systemd 部署示例

```ini
# /etc/systemd/system/ip-visitor.service
[Unit]
After=network-online.target

[Service]
WorkingDirectory=/opt/ip-visitor
ExecStart=/usr/bin/node src/server.js
Restart=always
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

`AmbientCapabilities=CAP_NET_RAW` 使 node 具备抓包能力，无需 root。

## API（均需登录 Cookie；标注 🔒 的仅管理员，viewer 只读账号无权调用）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /login | {user, password} 登录 |
| POST | /logout | 登出 |
| GET  | /api/session | 当前登录身份（user/role）+ 监听对象 + tcpdump 可用性 |
| GET  | /api/overview | 总量统计 |
| GET  | /api/records | 历史记录 ?ip=&port=&proto=&from=&to=&page=&size= |
| GET  | /api/clients | 客户端统计 ?from= |
| GET  | /api/clients/:ip | 单客户端端口明细 + 最近记录 |
| GET  | /api/alerts | 告警列表 ?limit= |
| POST | /api/alerts/test | 🔒 发送测试告警（验证 SSE/webhook 链路） |
| POST | /api/captures | 🔒 发起定向抓包 {target?, ip?, port?, proto?, seconds} |
| POST | /api/captures/stop | 🔒 停止当前抓包（按正常完成处理） |
| GET  | /api/captures | 抓包任务列表 |
| GET  | /api/captures/hosts | 可抓包目标（本机 + 远程主机） |
| GET  | /api/captures/packets | 抓包报文分页解析 ?id=&page=&size=&q=（q=显示过滤，返回 matched 计数，不含 hex） |
| GET  | /api/captures/packet | 单包详情 ?id=&no=（解码字段 + 载荷解码 + 全量 hex） |
| GET  | /api/captures/analyze | 抓包分析摘要（自动诊断结论 + 协议/标志/端口/来源/对话） ?id= |
| GET  | /api/captures/stream | 会话流还原 ?id=&a=&ap=&b=&bp=（对话双向载荷按时间排列） |
| GET  | /api/captures/download?id= | 下载 pcap |
| GET/POST/DELETE | /api/remote-hosts | 🔒 页面管理远程抓包主机（增删改，密码不回显，写回 config.json 热生效） |
| POST | /api/mode/real | 🔒 运行时从回放模式切换到真实抓包 |
| GET  | /api/users | 🔒 用户列表 |
| POST | /api/users | 🔒 新建用户 {user, password, role: admin\|viewer} |
| POST | /api/users/password | 改密码：admin 可改任何人；自己改需验证旧密码 |
| DELETE | /api/users/:name | 🔒 删除用户（不能删自己，至少保留一个管理员） |
| GET  | /api/stream | SSE 实时推送（record / alert 事件） |

## 已知限制

- 解析的是 tcpdump 文本输出（`-l -nn -tttt -q`），tcpdump 大版本间格式差异可能影响解析
- TCP/UDP 字节数为负载长度；ICMP 记录类型描述行中的 length
- IPv6 地址按 tcpdump 显示形式存储（小写），不展开压缩形式
