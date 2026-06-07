"""报告导出 — CSV / TXT / HTML 格式"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Finding, GeoInfo


def _geo_summary(geo: Optional[GeoInfo]) -> str:
    if geo is None:
        return ""
    return geo.summary()


def export_csv(
    file_path: str,
    findings: list[Finding],
    ip_geo: Optional[dict[str, GeoInfo]] = None,
) -> None:
    """导出 CSV 格式报告"""
    with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        headers = ["行号", "IP", "地理位置", "风险分", "攻击类型", "命中特征", "解码后内容", "原始日志"]
        writer.writerow(headers)
        for item in findings:
            geo_str = _geo_summary(ip_geo.get(item.ip)) if ip_geo else ""
            writer.writerow([
                item.line_no,
                item.ip,
                geo_str,
                item.score,
                item.categories,
                item.matched,
                item.normalized,
                item.raw,
            ])


def export_txt(
    file_path: str,
    findings: list[Finding],
    source_file: str = "",
    ip_stats: Optional[dict[str, int]] = None,
    ip_geo: Optional[dict[str, GeoInfo]] = None,
) -> None:
    """导出纯文本格式报告"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("Web攻击日志分析报告\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"源文件：{source_file}\n")
        f.write(f"命中记录：{len(findings)}\n")
        if ip_stats:
            f.write(f"攻击IP数：{len(ip_stats)}\n")
        f.write("\n" + "-" * 60 + "\n\n")

        if ip_stats:
            f.write("攻击IP统计\n")
            f.write("-" * 40 + "\n")
            sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)
            for ip, count in sorted_ips:
                geo_str = ""
                if ip_geo and ip in ip_geo:
                    geo_str = f"  [{_geo_summary(ip_geo[ip])}]"
                f.write(f"  {ip}  —  {count} 次{geo_str}\n")
            f.write("\n" + "-" * 60 + "\n\n")

        for idx, item in enumerate(findings, start=1):
            geo_str = ""
            if ip_geo and item.ip in ip_geo:
                geo_str = f" [{_geo_summary(ip_geo[item.ip])}]"
            f.write(f"[{idx}] 行号 {item.line_no}  IP={item.ip}{geo_str}  分数={item.score}\n")
            f.write(f"    类型：{item.categories}\n")
            f.write(f"    命中：{item.matched}\n")
            f.write(f"    解码：{item.normalized}\n")
            f.write(f"    原始：{item.raw}\n")
            f.write("-" * 60 + "\n")


def export_html(
    file_path: str,
    findings: list[Finding],
    source_file: str = "",
    ip_stats: Optional[dict[str, int]] = None,
    ip_geo: Optional[dict[str, GeoInfo]] = None,
) -> None:
    """导出 HTML 格式报告（带样式，适合浏览器查看）"""
    rows_html = ""
    for item in findings:
        geo_str = ""
        if ip_geo and item.ip in ip_geo:
            g = ip_geo[item.ip]
            geo_str = f"{g.flag()} {g.summary()}"
        rows_html += f"""
        <tr>
            <td>{item.line_no}</td>
            <td>{item.ip}</td>
            <td>{geo_str}</td>
            <td class="score">{item.score}</td>
            <td>{item.categories}</td>
            <td class="matched">{item.matched}</td>
            <td class="raw">{item.normalized}</td>
            <td class="raw">{item.raw}</td>
        </tr>"""

    ip_rows = ""
    if ip_stats:
        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips:
            geo_str = ""
            if ip_geo and ip in ip_geo:
                g = ip_geo[ip]
                geo_str = f"{g.flag()} {g.summary()}"
            ip_rows += f"""
            <tr>
                <td>{ip}</td>
                <td>{geo_str}</td>
                <td class="score">{count}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>日志分析报告</title>
<style>
    body {{ font-family: 'Microsoft YaHei', sans-serif; background: #0f172a; color: #e2e8f0; margin: 40px; }}
    h1 {{ color: #f8fafc; }}
    h2 {{ color: #93c5fd; margin-top: 30px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
    th {{ background: #1e293b; padding: 10px 8px; text-align: left; }}
    td {{ padding: 8px; border-bottom: 1px solid #334155; }}
    tr:nth-child(even) {{ background: #172033; }}
    .score {{ text-align: center; font-weight: bold; color: #f87171; }}
    .matched {{ color: #fbbf24; }}
    .raw {{ font-family: monospace; font-size: 12px; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .meta {{ color: #94a3b8; margin-bottom: 20px; }}
</style>
</head>
<body>
<h1>🛡️ Web攻击日志分析报告</h1>
<p class="meta">
    生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
    源文件：{source_file}<br>
    命中记录：{len(findings)} 条
    {f' | 攻击IP：{len(ip_stats)} 个' if ip_stats else ''}
</p>

<h2>🔍 攻击详情</h2>
<table>
<thead><tr><th>行号</th><th>IP</th><th>地理位置</th><th>风险分</th><th>类型</th><th>命中特征</th><th>解码内容</th><th>原始日志</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
{"<h2>📊 攻击IP统计</h2><table><thead><tr><th>IP</th><th>地理位置</th><th>攻击次数</th></tr></thead><tbody>" + ip_rows + "</tbody></table>" if ip_rows else ""}
</body>
</html>"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html)


def export_report(
    file_path: str,
    findings: list[Finding],
    source_file: str = "",
    ip_stats: Optional[dict[str, int]] = None,
    ip_geo: Optional[dict[str, GeoInfo]] = None,
) -> None:
    """
    自动根据文件后缀选择导出格式。
    支持：.csv / .txt / .html
    """
    suffix = Path(file_path).suffix.lower()
    if suffix == ".csv":
        export_csv(file_path, findings, ip_geo)
    elif suffix in (".htm", ".html"):
        export_html(file_path, findings, source_file, ip_stats, ip_geo)
    else:
        export_txt(file_path, findings, source_file, ip_stats, ip_geo)
