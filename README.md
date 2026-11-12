# 🛡️ Web攻击日志分析工具

> 自动化检测 SQL注入 / XSS / 扫描器 / 路径穿越 / Python日志中的攻击行为

基于 Python + PyQt5 的桌面 GUI 工具，拖拽日志文件即可分析，支持 Apache/Nginx 通用日志、JSON 日志和 Python 源码日志。

---

## 📦 版本说明

本仓库包含两个版本：

| 版本 | 目录 | 说明 |
|---|---|---|
| **v1_original** | `v1_original/` | 原始单文件版 (~970 行) |
| **v2_modular** | `v2_modular/` | 模块化重构版（推荐） |

---

## ✨ 功能特性 (v2_modular)

- ✅ **规则外部化** — 攻击检测规则存储在 `rules.json`，无需改代码即可增删改规则
- ✅ **可配置阈值** — GUI 中实时调整风险分数阈值，即时过滤结果
- ✅ **IP/模式白名单** — 支持按 IP、正则表达式、攻击类别设置白名单
- ✅ **流式处理** — 日志分块解码、逐条分析，后台协作取消并分批刷新；Python 源码 AST 解析仍需载入源码，单次解析不可中断
- ✅ **关键词高亮** — 命中特征列自动高亮显示匹配的关键词
- ✅ **搜索过滤** — 按 IP、攻击类型、特征、完整内容和分数范围筛选；排序、详情选择及可见行导出保持记录对应
- ✅ **明确任务结果** — 区分完成、取消、读取失败和分析失败；部分命中仍可检查和导出并注明状态
- ✅ **IP 地理位置** — 支持 GeoLite2 离线数据库和 ipinfo.io API；查询在后台执行
- ✅ **多种导出** — 支持 CSV / TXT / HTML；原子写入、保留完整证据并转义 HTML/电子表格危险内容
- ✅ **暗色主题** — 护眼深色界面
- ✅ **单元测试** — 328 个测试覆盖解析、分析、线程、GUI、配置和导出

---

## 🖼️ 截图

> <img width="1302" height="937" alt="image" src="https://github.com/user-attachments/assets/d9e03b32-768b-48e6-ba37-47f5e2032b67" />


---

## 🚀 快速开始

### 环境要求

- Python 3.10+
- PyQt5

### 安装依赖

```bash
cd v2_modular
pip install -r requirements.txt
```

### 启动 GUI

```bash
cd v2_modular
python -m log_analyzer.main
```

### 运行测试

```bash
cd v2_modular
python -m pytest tests -v
```

---

## 📁 项目结构 (v2_modular)

```
v2_modular/
├── log_analyzer/              # 主包
│   ├── main.py                # 入口点
│   ├── models.py              # 数据模型
│   ├── rules.py               # 规则引擎
│   ├── parser.py              # 日志解析器
│   ├── analyzer.py            # 流式分析引擎
│   ├── whitelist.py           # 白名单管理
│   ├── config.py              # 配置管理
│   ├── geoip.py               # IP 地理位置
│   ├── export.py              # 报告导出
│   ├── paths.py               # 源码/打包资源及用户数据路径
│   ├── persistence.py         # 原子 JSON 持久化
│   └── gui/                   # GUI 组件
│       ├── main_window.py     # 主窗口
│       ├── worker.py          # 后台工作线程
│       ├── widgets.py         # 自定义控件
│       └── highlight_delegate.py  # 关键词高亮
├── tests/                     # 单元测试
├── rules.json                 # 攻击检测规则
├── config.json                # 用户配置
├── whitelist.json             # 白名单
└── requirements.txt           # 依赖清单
```
<img width="982" height="634" alt="image" src="https://github.com/user-attachments/assets/ee3c4b38-4400-4d15-8428-cb82637c6e3b" />


---

## 📋 支持的日志格式

- **Apache/Nginx 通用日志** — 标准 Combined Log Format
- **JSON 日志** — 自动识别 `ip`、`request`、`message` 等字段
- **Python 源码** (`.py`) — 通过 AST 提取 `print()`、`logging` 调用中的日志文本
- **纯文本** — 逐行读取，提取 IP 和内容

---

## ⚙️ 配置说明

### 规则文件 (`rules.json`)

```json
{
  "categories": {
    "SQL Injection": {
      "keywords": {
        "union": 2,
        "select": 1,
        "sleep(": 5
      },
      "advanced_patterns": [
        {"pattern": "union\\s+select", "score": 4}
      ]
    }
  }
}
```

每个关键词可单独配置分数，支持正则高级模式。

### 白名单 (`whitelist.json`)

```json
{
  "ips": ["127.0.0.1", "192.168.1.1"],
  "patterns": ["/healthcheck"],
  "categories": []
}
```

---

## 📦 打包为 exe

```bash
cd v2_modular
pip install pyinstaller
pyinstaller log_analyzer.spec
```

当前 spec 生成单文件 `v2_modular/dist/LogAnalyzer.exe`。打包版会把默认 JSON 首次复制到 `%APPDATA%/LogAnalyzer/`，配置与白名单的修改保存在用户目录；已存在的用户文件（包括损坏文件）不会被默认值覆盖。源码运行时默认仍使用仓库内的 JSON 文件。

---

## 🧪 检测类型

| 攻击类型 | 示例特征 |
|---|---|
| **SQL 注入** | `union select`、`or 1=1`、`sleep(`、`information_schema` |
| **XSS** | `<script>`、`alert(`、`onerror=`、`onload=` |
| **扫描器** | `sqlmap`、`nikto`、`nmap`、`acunetix` |
| **路径穿越** | `../`、`/etc/passwd`、`boot.ini` |

---

## 📄 开源协议

MIT License
