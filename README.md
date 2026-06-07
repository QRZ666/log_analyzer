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
- ✅ **流式处理** — 逐行分析，大文件不卡界面，支持实时取消
- ✅ **关键词高亮** — 命中特征列自动高亮显示匹配的关键词
- ✅ **搜索过滤** — 按 IP、攻击类型、特征、分数范围实时过滤结果
- ✅ **IP 地理位置** — 支持 GeoLite2 离线数据库和 ipinfo.io API
- ✅ **多种导出** — 支持 CSV / TXT / HTML 格式报告导出
- ✅ **暗色主题** — 护眼深色界面
- ✅ **单元测试** — 62 个测试覆盖核心逻辑

---

## 🖼️ 截图

> （待补充）

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

生成的可执行文件在 `v2_modular/dist/LogAnalyzer/LogAnalyzer.exe`。

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
