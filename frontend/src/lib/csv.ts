// ============================================================================
// CSV 내보내기 공통 — **주입 방어와 인코딩이 화면마다 갈리지 않게** 한 곳에 둔다.
//
// 이 파일이 생긴 이유: 조치 필요 항목 화면에만 있던 규칙을 트랙② 화면이 다시 적을 참이었다.
// 수식 주입 방어가 두 벌이 되면 한쪽만 고쳐지고, 그 사실은 아무도 모른다(CSV 는 화면에서
// 검증되지 않는 산출물이다).
// ============================================================================

// CSV formula injection 무력화. 셀 앞글자가 = + - @ tab CR LF 이면 ' 프리픽스로
// 스프레드시트가 수식으로 해석하지 못하게 한다. 엔진 m6_reporter._csv_safe(_CSV_INJECT_RE)와 동일 규칙.
export function csvSafe(s: string): string {
  return /^[=+\-@\t\r\n]/.test(s) ? "'" + s : s;
}

// 한 행을 RFC 4180 으로 감싼다(모든 셀을 항상 인용 — 쉼표·줄바꿈·한국어가 섞인다).
export function csvRow(cells: string[]): string {
  return cells.map((c) => `"${csvSafe(c).replace(/"/g, '""')}"`).join(",");
}

export function toCsv(header: string[], rows: string[][]): string {
  return [csvRow(header), ...rows.map(csvRow)].join("\n");
}

export function downloadCsv(filename: string, header: string[], rows: string[][]): void {
  // UTF-8 BOM + charset 선언. 셀 값에 한국어가 들어가는데, BOM 이 없으면 Windows Excel 이 CSV 를
  // 로컬 코드페이지로 읽어 전부 깨진다(ko-KR 은 CP949). BOM 이 있으면 Excel·LibreOffice·Numbers
  // 모두 UTF-8 로 인식한다. utf-8-sig 로 읽는 쪽(pandas·csv 모듈)에서도 문제가 없다.
  const blob = new Blob(["\ufeff" + toCsv(header, rows)], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
