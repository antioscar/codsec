from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem,
    QHBoxLayout, QProgressBar,
)
from PySide6.QtCore import Qt

from src.report.compliance import evaluate_compliance
from src.models import ScanReport

SEV_COLORS = {"critical": "#DC143C", "high": "#FF4500", "medium": "#FFA500", "low": "#228B22", "compliant": "#228B22"}


class ComplianceTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        header = QLabel("Cumplimiento de Normas de Seguridad")
        header.setStyleSheet("font-size:16px; font-weight:bold; color:#7ec8e3; padding:8px 0;")
        layout.addWidget(header)

        self.score_layout = QHBoxLayout()
        layout.addLayout(self.score_layout)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Control", "Título", "Estado", "Hallazgos", "Severidad"])
        self.tree.setColumnWidth(0, 120)
        self.tree.setColumnWidth(1, 280)
        self.tree.setColumnWidth(2, 100)
        self.tree.setColumnWidth(3, 80)
        self.tree.setColumnWidth(4, 120)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet("""
            QTreeWidget::item { padding: 4px 6px; }
            QTreeWidget::item:alternate { background: #1e1e36; }
            QHeaderView::section { background: #2a2a4a; padding: 4px; }
        """)
        layout.addWidget(self.tree)

    def set_compliance(self, report: ScanReport):
        self.tree.clear()

        for i in reversed(range(self.score_layout.count())):
            self.score_layout.itemAt(i).widget().setParent(None)

        compliance = evaluate_compliance(report)

        for std_label, std_data in compliance.items():
            pct = std_data["compliance_percentage"]
            pct_color = "#228B22" if pct >= 80 else ("#FFA500" if pct >= 50 else "#DC143C")

            std_item = QTreeWidgetItem([
                std_label,
                f"{std_data['controls_compliant']}/{std_data['controls_evaluated']} controles",
                f"{pct}%",
                str(sum(c["total_findings"] for c in std_data["details"].values())),
                "",
            ])
            std_item.setForeground(0, Qt.GlobalColor.cyan)

            font = std_item.font(0)
            font.setBold(True)
            std_item.setFont(0, font)

            for cid, cinfo in std_data["details"].items():
                status_text = "Cumplido" if cinfo["status"] == "compliant" else "Incumplido"
                sev_summary = ", ".join(f"{sev}:{cnt}" for sev, cnt in sorted(cinfo.get("by_severity", {}).items()))

                child = QTreeWidgetItem([
                    cid,
                    cinfo["title"],
                    status_text,
                    str(cinfo["total_findings"]),
                    sev_summary,
                ])

                if cinfo["status"] == "compliant":
                    child.setForeground(2, Qt.GlobalColor.darkGreen)
                else:
                    child.setForeground(2, Qt.GlobalColor.red)

                std_item.addChild(child)

            self.tree.addTopLevelItem(std_item)

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(int(pct))
            bar.setTextVisible(True)
            bar.setFormat(f"{std_label.split('(')[0].strip()}: {pct}%")
            bar.setStyleSheet(f"""
                QProgressBar {{ background:#22223a; border:1px solid #3a3a5c; border-radius:4px; height:20px; text-align:center; color:#c0c0d0; font-size:11px; }}
                QProgressBar::chunk {{ background:{pct_color}; border-radius:3px; }}
            """)
            self.score_layout.addWidget(bar)

        self.tree.expandAll()
