# log_analyzer
# Web攻击日志分析工具（Web Attack Log Analyzer）

## 项目简介

本项目是一个基于 Python + PyQt5 开发的桌面日志分析工具，用于分析 Web 访问日志中的可疑攻击行为。

工具面向网络安全学习场景，可用于快速识别常见 Web 攻击特征，包括：

* SQL 注入（SQL Injection）
* 跨站脚本攻击（XSS）
* 路径穿越（Path Traversal）
* 扫描器行为识别（Scanner Detection）

支持图形界面操作、日志拖拽导入、多线程分析、风险评分以及结果导出。

---

## 核心功能

### 1. 攻击检测能力

支持基于规则的检测：

* SQL 注入特征
  例如：`UNION SELECT`、`OR 1=1`、`SLEEP()`、`information_schema`

* XSS 特征
  例如：`<script>`、`alert()`、`onerror`、`javascript:` 等

* 路径穿越
  例如：`../`、`/etc/passwd`、`boot.ini`

* 扫描器识别
  例如：`sqlmap`、`nmap`、`nikto`、`gobuster`

---

### 2. 图形化界面（GUI）

基于 PyQt5 实现，支持：

* 文件拖拽导入日志
* 文件选择器导入
* 实时分析进度条
* 攻击结果表格展示
* 单条日志详情查看

---

### 3. 分析结果展示

每条命中记录包含：

* 行号
* 源 IP
* 风险评分
* 攻击类型
* 命中关键特征
* 解码后的请求内容
* 原始日志内容

---

### 4. IP攻击统计

自动统计攻击来源 IP，并按攻击次数排序展示，用于快速定位高频攻击源。

---

### 5. 报告导出

支持导出：

* CSV 文件
* TXT 文本报告

导出内容包括：

* 攻击记录
* 风险评分
* 命中规则
* 解码内容
* 原始日志

---

## 支持的日志格式

### Apache / Nginx 标准日志

```
192.168.1.100 - - [01/Jun/2026:12:00:00 +0800] "GET /index.php?id=1' OR '1'='1 HTTP/1.1"
```

### 简化日志

```
192.168.1.103 sqlmap
```

### 测试日志

```
192.168.1.101 GET /?q=<script>alert(1)</script> HTTP/1.1
192.168.1.102 GET /../../../../etc/passwd HTTP/1.1
```

---

## 技术栈

* Python 3.10
* PyQt5
* 正则表达式（Regex）
* 多线程（QThread）
* 文件解析与编码处理

---

## 安装与运行

### 安装依赖

```
pip install PyQt5
```

### 运行项目

```
python log_analyzer.py
```

---

## 打包成可执行文件

```
pyinstaller -F -w log_analyzer.py
```

参数说明：

* `-F`：打包为单文件
* `-w`：关闭控制台窗口（GUI模式）

生成路径：

```
dist/log_analyzer.exe
```

---

## 项目亮点

* 规则引擎 + 风险评分机制
* 支持多类型 Web 攻击检测
* GUI 可视化分析流程
* 支持拖拽式操作，降低使用门槛
* 多线程避免界面卡死

---

## 后续可扩展方向

* GeoIP 攻击源定位
* OWASP Top 10 完整覆盖
* ModSecurity 日志解析
* 攻击趋势图表可视化
* PDF 报告生成
* 实时日志监控

---

## 项目用途说明

本项目用于网络安全学习与日志分析实践，不应用于非法用途。
