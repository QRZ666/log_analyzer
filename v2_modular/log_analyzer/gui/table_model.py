"""结果表格模型：保存原始发现，由代理负责排序和筛选，不复制/重建单元格。"""

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt

from ..models import Finding, GeoInfo


class FindingsTableModel(QAbstractTableModel):
    HEADERS = ("行号", "IP", "地理位置", "风险分", "类型", "命中特征")
    SORT_ROLE = Qt.UserRole + 1

    def __init__(self, findings=None, ip_geo=None, parent=None):
        super().__init__(parent)
        self.findings: list[Finding] = findings if findings is not None else []
        self.ip_geo: dict[str, GeoInfo] = ip_geo if ip_geo is not None else {}
        self.show_geo = False
        self._rows_by_ip: dict[str, list[int]] = {}
        for row, finding in enumerate(self.findings):
            self._rows_by_ip.setdefault(finding.ip, []).append(row)

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.findings)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        return super().headerData(section, orientation, role)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.findings):
            return None
        item = self.findings[index.row()]
        column = index.column()
        if role == Qt.UserRole:
            # 记录随模型索引映射，而不是拿表格行号反查未排序的列表。
            return item
        if role == Qt.TextAlignmentRole and column in (0, 3):
            return int(Qt.AlignCenter)
        if role not in (Qt.DisplayRole, Qt.ToolTipRole, self.SORT_ROLE):
            return None
        geo = self.ip_geo.get(item.ip) if self.show_geo else None
        values = (
            item.line_no,
            item.ip,
            geo.summary() if geo else "",
            item.score,
            item.categories,
            item.matched,
        )
        if not 0 <= column < len(values):
            return None
        value = values[column]
        if role == Qt.ToolTipRole:
            return str(value)
        # 保留 int，确保 2、10、100 按数值而不是字符串排序。
        return value

    def append_findings(self, findings: list[Finding]):
        if not findings:
            return
        start = len(self.findings)
        self.beginInsertRows(QModelIndex(), start, start + len(findings) - 1)
        self.findings.extend(findings)
        for row, finding in enumerate(findings, start):
            self._rows_by_ip.setdefault(finding.ip, []).append(row)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self.findings.clear()
        self.ip_geo.clear()
        self._rows_by_ip.clear()
        self.endResetModel()

    def set_geo_visible(self, visible: bool):
        if self.show_geo == visible:
            return
        self.show_geo = visible
        if self.findings:
            self.dataChanged.emit(
                self.index(0, 2), self.index(len(self.findings) - 1, 2),
                [Qt.DisplayRole, Qt.ToolTipRole, self.SORT_ROLE],
            )

    def update_geo(self, infos: list[GeoInfo]):
        rows = []
        for info in infos:
            self.ip_geo[info.ip] = info
            rows.extend(self._rows_by_ip.get(info.ip, ()))
        if self.show_geo and rows:
            # 合并为一个区域通知，避免每个单元格都触发一次重绘/排序。
            self.dataChanged.emit(
                self.index(min(rows), 2), self.index(max(rows), 2),
                [Qt.DisplayRole, Qt.ToolTipRole, self.SORT_ROLE],
            )


class FindingsFilterProxyModel(QSortFilterProxyModel):
    """同一套条件用于已有行和后续批次，避免筛选被分析完成/GeoIP刷新覆盖。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ""
        self._minimum = 0
        self._maximum = 2147483647
        self.setDynamicSortFilter(True)
        self.setSortCaseSensitivity(Qt.CaseInsensitive)
        self.setSortRole(FindingsTableModel.SORT_ROLE)

    def set_filters(self, text="", min_score=0, max_score=2147483647, threshold=0):
        values = (text.casefold(), max(min_score, threshold), max_score)
        if values == (self._text, self._minimum, self._maximum):
            return
        self._text, self._minimum, self._maximum = values
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        item = model.data(model.index(source_row, 0, source_parent), Qt.UserRole)
        if item is None or not self._minimum <= item.score <= self._maximum:
            return False
        if not self._text:
            return True
        return any(self._text in value.casefold() for value in (
            item.ip, item.categories, item.matched, item.normalized, item.raw,
        ))

    def visible_findings(self) -> list[Finding]:
        """按用户当前看到的排序返回导出快照。"""
        return [self.index(row, 0).data(Qt.UserRole) for row in range(self.rowCount())]
