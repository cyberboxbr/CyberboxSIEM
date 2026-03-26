import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// ── CSV Export ────────────────────────────────────────────────────────────────

export function exportCsv(
  rows: Array<Record<string, unknown>>,
  columns: string[],
  filename: string,
) {
  const header = columns.join(',');
  const body = rows
    .map((row) =>
      columns
        .map((col) => {
          const value = row[col];
          const text = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
          return text.includes(',') || text.includes('"') || text.includes('\n')
            ? `"${text.replace(/"/g, '""')}"`
            : text;
        })
        .join(','),
    )
    .join('\n');
  const blob = new Blob([`${header}\n${body}`], { type: 'text/csv;charset=utf-8;' });
  downloadBlob(blob, `${filename}.csv`);
}

// ── PDF Export ────────────────────────────────────────────────────────────────

interface PdfReportOptions {
  title: string;
  subtitle?: string;
  filename: string;
  columns: string[];
  rows: Array<Record<string, unknown>>;
  kpis?: Array<{ label: string; value: string }>;
}

export function exportPdf({ title, subtitle, filename, columns, rows, kpis }: PdfReportOptions) {
  const doc = new jsPDF({ orientation: rows.length > 0 && columns.length > 6 ? 'landscape' : 'portrait' });
  const pageWidth = doc.internal.pageSize.getWidth();

  // Header
  doc.setFontSize(8);
  doc.setTextColor(120);
  doc.text('CYBERBOX SECURITY', 14, 12);
  doc.text(new Date().toLocaleString(), pageWidth - 14, 12, { align: 'right' });

  // Title
  doc.setFontSize(18);
  doc.setTextColor(30);
  doc.text(title, 14, 24);

  if (subtitle) {
    doc.setFontSize(10);
    doc.setTextColor(100);
    doc.text(subtitle, 14, 31);
  }

  let yPos = subtitle ? 38 : 32;

  // KPIs row
  if (kpis && kpis.length > 0) {
    const kpiWidth = (pageWidth - 28) / kpis.length;
    kpis.forEach((kpi, i) => {
      const x = 14 + i * kpiWidth;
      doc.setFillColor(245, 245, 250);
      doc.roundedRect(x, yPos, kpiWidth - 4, 16, 2, 2, 'F');
      doc.setFontSize(7);
      doc.setTextColor(120);
      doc.text(kpi.label.toUpperCase(), x + 4, yPos + 5);
      doc.setFontSize(14);
      doc.setTextColor(30);
      doc.text(kpi.value, x + 4, yPos + 13);
    });
    yPos += 22;
  }

  // Table
  if (rows.length > 0) {
    const tableData = rows.map((row) =>
      columns.map((col) => {
        const val = row[col];
        if (val == null) return '';
        if (typeof val === 'object') return JSON.stringify(val).slice(0, 80);
        const str = String(val);
        return str.length > 80 ? `${str.slice(0, 77)}...` : str;
      }),
    );

    autoTable(doc, {
      startY: yPos,
      head: [columns],
      body: tableData,
      styles: { fontSize: 7, cellPadding: 2 },
      headStyles: { fillColor: [10, 31, 68], textColor: [255, 255, 255], fontSize: 7 },
      alternateRowStyles: { fillColor: [248, 248, 252] },
      margin: { left: 14, right: 14 },
    });
  } else {
    doc.setFontSize(10);
    doc.setTextColor(150);
    doc.text('No data available for the selected criteria.', 14, yPos + 10);
  }

  // Footer on each page
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageHeight = doc.internal.pageSize.getHeight();
    doc.setFontSize(7);
    doc.setTextColor(150);
    doc.text(`Cyberbox Security — Confidential`, 14, pageHeight - 8);
    doc.text(`Page ${i} of ${pageCount}`, pageWidth - 14, pageHeight - 8, { align: 'right' });
  }

  doc.save(`${filename}.pdf`);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
