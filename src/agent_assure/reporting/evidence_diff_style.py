from __future__ import annotations


def evidence_diff_css() -> str:
    return """
:root {
  color-scheme: light;
  --screen: #dfe7f0;
  --page: #ffffff;
  --panel: #f8fafc;
  --panel-strong: #eef4f8;
  --ink: #111827;
  --muted: #536171;
  --subtle: #718096;
  --border: #d5deea;
  --border-strong: #aebdcb;
  --navy: #0d1b2a;
  --slate: #1b2b3f;
  --teal: #0f766e;
  --teal-bg: #e6f6f3;
  --teal-border: #8ed4cc;
  --green: #166534;
  --green-bg: #e8f6ee;
  --green-border: #8fcaa7;
  --red: #b42318;
  --red-bg: #fff1f0;
  --red-border: #f2ada7;
  --amber: #8a5a00;
  --amber-bg: #fff7df;
  --amber-border: #eac96b;
  --blue: #155e75;
  --blue-bg: #e6f5f8;
  --blue-border: #91cdd9;
  --shadow: 0 18px 45px rgba(13, 27, 42, 0.16);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
  line-height: 1.42;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  color: var(--ink);
  background: var(--screen);
}
main {
  width: min(100%, 11.5in);
  margin: 0 auto;
  padding: 26px 18px 46px;
}
h1,
h2,
h3 {
  letter-spacing: 0;
}
h1 {
  max-width: 820px;
  font-size: 48px;
  line-height: 1.08;
  margin: 0;
  text-wrap: balance;
}
h2 {
  font-size: 22px;
  line-height: 1.2;
  margin: 0 0 10px;
}
p {
  margin: 0;
}
.page {
  width: 11in;
  max-width: 100%;
  min-height: 8.5in;
  margin: 0 auto 24px;
  padding: 0.42in;
  display: flex;
  flex-direction: column;
  background: var(--page);
  border: 1px solid rgba(174, 189, 203, 0.7);
  border-radius: 8px;
  box-shadow: var(--shadow);
  page-break-after: always;
  break-after: page;
}
.page:last-child {
  page-break-after: auto;
  break-after: auto;
}
.page > section + section {
  margin-top: 16px;
}
.eyebrow {
  margin: 0 0 10px;
  color: var(--teal);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0;
  text-transform: uppercase;
}
.subtitle {
  max-width: 760px;
  margin: 18px 0 0;
  color: rgba(255, 255, 255, 0.88);
  font-size: 18px;
  font-weight: 600;
}
.report-label {
  margin: 12px 0 0;
  color: rgba(255, 255, 255, 0.78);
}
.hero-page {
  color: #ffffff;
  background: var(--navy);
  border-color: #24364c;
}
.hero-page h1,
.hero-page h2 {
  color: #ffffff;
}
.hero {
  border-top: 0;
  padding: 0;
}
.hero-copy {
  max-width: 920px;
}
.hero .eyebrow {
  color: #78d6ce;
}
.hero-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  align-items: center;
  max-width: 900px;
  margin: 22px 0 0;
}
.hero-meta span {
  color: rgba(255, 255, 255, 0.78);
  font-size: 12px;
  font-weight: 750;
  text-transform: uppercase;
}
.hero-meta strong {
  min-width: 0;
  overflow-wrap: anywhere;
  color: #ffffff;
  font-size: 13px;
}
.signal-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin: 28px 0 0;
}
.signal {
  min-height: 146px;
  padding: 15px;
  border: 1px solid rgba(255, 255, 255, 0.16);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.08);
  display: grid;
  grid-template-rows: auto auto auto auto 1fr;
  align-content: start;
  gap: 7px;
}
.signal-icon {
  width: 28px;
  height: 28px;
  display: inline-grid;
  place-items: center;
  border: 1px solid currentColor;
  border-radius: 8px;
  font-weight: 900;
}
.signal-good .signal-icon {
  color: #8ee0a8;
}
.signal-bad .signal-icon {
  color: #ffaca5;
}
.signal-expected .signal-icon {
  color: #7dd3fc;
}
.signal-warn .signal-icon {
  color: #f5cf70;
}
.signal-label {
  display: block;
  color: rgba(255, 255, 255, 0.8);
  font-size: 13px;
  font-weight: 760;
}
.signal-value {
  display: block;
  min-width: 0;
  overflow-wrap: anywhere;
  color: #ffffff;
  font-size: 21px;
  font-weight: 800;
}
.signal-state {
  display: inline-block;
  width: fit-content;
  align-self: start;
  justify-self: start;
  padding: 3px 8px;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.12);
  color: #ffffff;
  font-size: 12px;
  font-weight: 800;
}
.signal-note {
  display: block;
  color: rgba(255, 255, 255, 0.76);
  font-size: 12px;
}
.hero-summary-row {
  display: grid;
  grid-template-columns: 1.25fr 0.8fr;
  gap: 28px;
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid rgba(142, 212, 204, 0.28);
}
.executive-extract,
.trust-boundary-note {
  min-width: 0;
}
.executive-extract h2,
.trust-boundary-note h2 {
  margin: 0 0 8px;
  color: rgba(255, 255, 255, 0.92);
  font-size: 14px;
  text-transform: uppercase;
}
.executive-extract ul {
  margin: 0;
  padding-left: 18px;
}
.executive-extract li {
  margin: 5px 0;
  color: rgba(255, 255, 255, 0.84);
  font-size: 14px;
}
.executive-extract strong {
  color: #ffffff;
}
.trust-boundary-note p {
  color: rgba(255, 255, 255, 0.82);
  font-size: 13px;
}
.trust-boundary-note p + p {
  margin-top: 10px;
  color: rgba(255, 255, 255, 0.74);
  font-size: 12px;
}
.page-footer {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  margin-top: auto;
  padding-top: 18px;
  color: var(--subtle);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0;
}
.hero-page .page-footer {
  color: rgba(255, 255, 255, 0.58);
}
.page-number {
  white-space: nowrap;
}
.section-lede {
  max-width: 840px;
  color: var(--muted);
  font-size: 16px;
  font-weight: 580;
}
.status-legend,
.section-note {
  margin: 10px 0 0;
  color: var(--muted);
  font-size: 14px;
}
.decision-section,
.key-finding,
.findings-section,
.missing-link-section,
.technical-detail,
.appendix-section,
.ci-gate-section,
.claim-boundary,
.packet-grid section {
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: #ffffff;
}
.page-intro {
  padding: 0 0 4px;
}
.process-diff-section {
  padding: 0;
}
.key-finding,
.findings-section {
  border-left: 5px solid var(--red);
}
.key-finding-clear {
  border-left-color: var(--green);
}
.claim-boundary {
  border-left: 5px solid var(--slate);
  background: var(--panel);
}
.ci-gate-section {
  border-left: 5px solid var(--blue);
  background: var(--blue-bg);
  border-color: var(--blue-border);
}
.evidence-diagram {
  display: grid;
  gap: 10px;
  margin: 20px 0 16px;
}
.diagram-row {
  display: grid;
  grid-template-columns: 170px minmax(0, 1fr) 280px;
  align-items: center;
  gap: 14px;
  min-height: 72px;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
}
.diagram-row-good {
  border-left: 5px solid var(--green);
}
.diagram-row-bad {
  border-left: 5px solid var(--red);
}
.diagram-row-gate {
  border-left: 5px solid var(--blue);
  background: var(--blue-bg);
}
.diagram-label {
  color: var(--muted);
  font-size: 12px;
  font-weight: 850;
  text-transform: uppercase;
}
.diagram-chain {
  min-width: 0;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  color: var(--ink);
  font-size: 17px;
  font-weight: 780;
}
.diagram-arrow {
  color: var(--subtle);
  font-weight: 900;
}
.diagram-state {
  color: var(--muted);
  font-size: 14px;
  font-weight: 760;
}
.diagram-row-good .diagram-state {
  color: var(--green);
}
.diagram-row-bad .diagram-state {
  color: var(--red);
}
.diagram-row-gate .diagram-state {
  color: var(--blue);
}
.section-heading-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
}
.section-heading-row h2 {
  margin: 0;
}
.regression-badge {
  display: inline-flex;
  align-items: center;
  min-height: 28px;
  padding: 4px 10px;
  border: 1px solid var(--red-border);
  border-radius: 8px;
  color: var(--red);
  background: var(--red-bg);
  font-size: 12px;
  font-weight: 800;
}
.table-wrap {
  width: 100%;
  overflow-x: auto;
}
.summary-grid,
dl {
  display: grid;
  grid-template-columns: minmax(170px, 260px) 1fr;
  gap: 8px 16px;
  margin: 0 0 16px;
}
dt {
  color: var(--muted);
  font-weight: 750;
}
dd {
  margin: 0;
  min-width: 0;
}
table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  table-layout: auto;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  background: #ffffff;
}
th, td {
  padding: 9px 10px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
  overflow-wrap: break-word;
}
td + td,
th + th {
  border-left: 1px solid var(--border);
}
th {
  color: #243244;
  background: var(--panel-strong);
  font-size: 12px;
  font-weight: 800;
  text-transform: uppercase;
  hyphens: none;
}
tbody tr:nth-child(even) td {
  background: #fbfdff;
}
tbody tr:last-child td {
  border-bottom: 0;
}
.process-row-unchanged td {
  background: #fbfdff;
}
.process-row-affected td,
.process-row-changed td {
  background: #fff8f8;
}
.process-diff-table td {
  min-width: 0;
}
.wide-table {
  min-width: 760px;
}
.process-diff-table {
  min-width: 0;
}
.process-evidence-table {
  min-width: 1240px;
}
.cell-value {
  min-width: 0;
}
code {
  display: inline-block;
  max-width: 100%;
  margin: 1px 0;
  padding: 1px 5px;
  border: 1px solid #dbe3ec;
  border-radius: 5px;
  color: #1d2b3a;
  background: #f6f8fb;
  font-family: Consolas, Monaco, monospace;
  font-size: 0.92em;
  white-space: nowrap;
  overflow-wrap: normal;
  word-break: normal;
}
code.wrap-token {
  white-space: normal;
  overflow-wrap: anywhere;
}
.process-diff-table code {
  font-size: 0.82em;
}
.state-good {
  color: var(--green);
  background: var(--green-bg);
  border-color: var(--green-border);
}
.state-bad {
  color: var(--red);
  background: var(--red-bg);
  border-color: var(--red-border);
}
.state-warn {
  color: var(--amber);
  background: var(--amber-bg);
  border-color: var(--amber-border);
}
.state-expected {
  color: var(--blue);
  background: var(--blue-bg);
  border-color: var(--blue-border);
}
.state-good,
.state-bad,
.state-warn,
.state-expected {
  display: inline-flex;
  align-items: center;
  width: fit-content;
  max-width: 100%;
  padding: 3px 9px;
  border: 1px solid;
  border-radius: 6px;
  font-weight: 800;
  white-space: nowrap;
  line-height: 1.25;
}
.diff-pair {
  display: grid;
  grid-template-columns: 72px minmax(0, 1fr);
  gap: 4px 10px;
}
.diff-label {
  color: var(--muted);
  font-weight: 800;
}
.diff-removed {
  display: inline-flex;
  align-items: baseline;
  gap: 4px;
  margin: 1px 0;
  padding: 2px 6px;
  border: 1px solid var(--red-border);
  border-radius: 5px;
  color: var(--red);
  background: var(--red-bg);
  white-space: nowrap;
  overflow-wrap: normal;
  word-break: normal;
}
.diff-removed-token {
  text-decoration: line-through;
  text-decoration-thickness: 1px;
}
.diff-removed .empty {
  color: var(--red);
}
.diff-marker {
  font-weight: 900;
  text-decoration: none;
}
.value-list {
  margin: 6px 0 0;
  padding-left: 18px;
}
.value-list li {
  min-width: 0;
  overflow-wrap: anywhere;
}
.value-count {
  color: var(--muted);
  font-weight: 700;
}
.technical-detail,
.appendix-section {
  color: #253244;
}
.technical-detail h2,
.appendix-section h2 {
  color: #253244;
}
.empty {
  color: var(--subtle);
}
.packet-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  margin: 0 0 16px;
}
.packet-grid section {
  min-width: 0;
}
.appendix-section code,
.packet-grid code,
.value-list code {
  white-space: normal;
  overflow-wrap: anywhere;
}
@media screen {
  .process-diff-table {
    border: 0;
    background: transparent;
  }
  .process-diff-table thead {
    display: none;
  }
  .process-diff-table,
  .process-diff-table tbody,
  .process-diff-table tr,
  .process-diff-table td {
    display: block;
  }
  .process-diff-table tr {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin: 0;
    padding: 10px;
    border: 1px solid var(--border);
    border-left: 5px solid var(--red);
    border-radius: 8px;
    background: #fff8f8;
  }
  .process-diff-table td {
    display: grid;
    grid-template-rows: auto minmax(0, 1fr);
    gap: 6px;
    min-width: 0;
    padding: 10px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #ffffff;
    overflow: hidden;
    overflow-wrap: normal;
    word-break: normal;
  }
  .process-diff-table td + td {
    border-left: 1px solid var(--border);
  }
  .process-diff-table td::before {
    content: attr(data-label);
    color: var(--muted);
    font-size: 11px;
    font-weight: 850;
    text-transform: uppercase;
  }
  .process-diff-table td:nth-child(5),
  .process-diff-table td:nth-child(6) {
    grid-column: span 2;
  }
  .process-diff-table td:nth-child(5) {
    border-color: var(--red-border);
    background: #fffafa;
  }
  .process-diff-table .cell-value,
  .process-diff-table .diff-pair > span {
    min-width: 0;
  }
  .process-diff-table code {
    font-size: 0.86em;
  }
  .process-diff-table .diff-pair {
    grid-template-columns: 78px minmax(0, 1fr);
  }
}
@media (max-width: 1120px) {
  .signal-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .diagram-row {
    grid-template-columns: 150px minmax(0, 1fr);
  }
  .diagram-state {
    grid-column: 2;
  }
}
@media (max-width: 820px) {
  main {
    padding: 18px 10px 34px;
  }
  .page {
    min-height: auto;
    padding: 22px;
  }
  h1 {
    font-size: 34px;
  }
  .signal-grid,
  .hero-summary-row,
  .packet-grid,
  dl {
    grid-template-columns: 1fr;
  }
  .diagram-row {
    grid-template-columns: 1fr;
  }
  .diagram-state {
    grid-column: auto;
  }
  .key-finding-table,
  .process-diff-table,
  .process-evidence-table {
    min-width: 0;
    border: 0;
    background: transparent;
  }
  .key-finding-table thead,
  .process-diff-table thead,
  .process-evidence-table thead {
    display: none;
  }
  .key-finding-table,
  .key-finding-table tbody,
  .key-finding-table tr,
  .key-finding-table td,
  .process-diff-table,
  .process-diff-table tbody,
  .process-diff-table tr,
  .process-diff-table td,
  .process-evidence-table,
  .process-evidence-table tbody,
  .process-evidence-table tr,
  .process-evidence-table td {
    display: block;
  }
  .key-finding-table tr,
  .process-diff-table tr,
  .process-evidence-table tr {
    margin: 0 0 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #ffffff;
  }
  .key-finding-table td,
  .process-diff-table td,
  .process-evidence-table td {
    display: grid;
    grid-template-columns: 132px minmax(0, 1fr);
    gap: 8px;
    min-width: 0;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    overflow-wrap: normal;
    word-break: normal;
  }
  .key-finding-table td + td,
  .process-diff-table td + td,
  .process-evidence-table td + td {
    border-left: 0;
  }
  .key-finding-table td:last-child,
  .process-diff-table td:last-child,
  .process-evidence-table td:last-child {
    border-bottom: 0;
  }
  .key-finding-table td::before,
  .process-diff-table td::before,
  .process-evidence-table td::before {
    content: attr(data-label);
    color: var(--muted);
    font-weight: 800;
  }
  .key-finding-table .cell-value,
  .process-diff-table .cell-value,
  .process-evidence-table .cell-value {
    min-width: 0;
    overflow-wrap: normal;
    word-break: normal;
  }
  .process-diff-table td {
    border: 0;
    border-bottom: 1px solid var(--border);
    border-radius: 0;
    background: #ffffff;
  }
  .process-diff-table td:nth-child(5),
  .process-diff-table td:nth-child(6) {
    grid-column: auto;
  }
  .process-diff-table td:nth-child(5) {
    background: #fff8f8;
  }
  .key-finding-table code {
    white-space: normal;
    overflow-wrap: anywhere;
  }
}
@media print {
  @page {
    size: letter landscape;
    margin: 0;
  }
  body {
    background: #ffffff;
  }
  main {
    width: auto;
    padding: 0;
  }
  .page {
    width: 11in;
    min-height: 8.5in;
    margin: 0;
    border: 0;
    border-radius: 0;
    box-shadow: none;
    break-inside: avoid;
  }
  .table-wrap {
    overflow: visible;
  }
  table {
    min-width: 0;
  }
  th {
    overflow-wrap: normal;
    word-break: normal;
    hyphens: none;
  }
  .wide-table {
    min-width: 0;
  }
  .process-diff-table code,
  .process-evidence-table code,
  .process-diff-table .state-good,
  .process-diff-table .state-bad,
  .process-diff-table .state-warn,
  .process-diff-table .state-expected,
  .process-evidence-table .state-good,
  .process-evidence-table .state-bad,
  .process-evidence-table .state-warn,
  .process-evidence-table .state-expected {
    white-space: nowrap;
    overflow-wrap: normal;
    word-break: normal;
  }
  .process-diff-table .diff-pair {
    grid-template-columns: 78px minmax(0, 1fr);
  }
  .appendix-section code {
    white-space: normal;
    overflow-wrap: anywhere;
  }
}
""".strip()
