import { useState } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Button from "@cloudscape-design/components/button";
import Spinner from "@cloudscape-design/components/spinner";
import Alert from "@cloudscape-design/components/alert";
import { api } from "@/api/client";
import { useAsync } from "@/api/useAsync";
import Table from "@cloudscape-design/components/table";
import { useAccounts } from "@/AccountContext";
import type { ReportRef, ExecSummary } from "@/api/types";

// Fetch the presigned URL into a blob to force a file download: the artifacts are served as
// text/*, so a plain href would make the browser open them in a new tab instead of saving.
//
// This deliberately has no window.open fallback. It used to fall back on any failure, which
// turned two distinct bugs into the same silent symptom -- "download" quietly behaved like
// "view" (CSP blocking the fetch) and an S3 error page opened as if it were the artifact.
// Failures now surface to the caller so the user sees what actually went wrong.
async function downloadUrl(url: string, filename: string): Promise<void> {
  const res = await fetch(url);
  if (!res.ok) {
    // S3 reports failures as an XML body; saving it would look like a corrupt artifact.
    throw new Error(`저장소 응답 ${res.status}`);
  }
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = objectUrl;
    a.download = filename;
    a.click();
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

function Value({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box fontSize="display-l" fontWeight="bold">{children}</Box>
    </div>
  );
}

export default function Reports() {
  // 선택 계정에 맞는 리포트(전체=""면 통합, 계정이면 그 계정). 계정 바뀌면 재조회.
  const { selected } = useAccounts();
  const { data, loading, error, reload } = useAsync<ReportRef>(
    () => api.getLatestReport(selected), [selected],
  );
  // Download failures are shown instead of being swallowed by a window.open fallback.
  const [downloadError, setDownloadError] = useState<string | null>(null);

  async function handleDownload(url: string, filename: string) {
    setDownloadError(null);
    try {
      await downloadUrl(url, filename);
    } catch (e) {
      setDownloadError(
        `${filename} 다운로드에 실패했습니다: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }

  if (loading) {
    return <Box padding="xxl" textAlign="center"><Spinner size="large" /></Box>;
  }
  if (error || !data) {
    return (
      <ContentLayout header={<Header variant="h1">리포트</Header>}>
        <Alert type="error" header="리포트를 불러오지 못했습니다"
          action={<Button onClick={reload}>다시 시도</Button>}>
          {error ?? "실행 이력이 없거나 리포트가 아직 생성되지 않았습니다. 대시보드에서 전체 조회를 먼저 실행하세요."}
        </Alert>
      </ContentLayout>
    );
  }

  const s = data.exec_summary;

  return (
    <ContentLayout header={<Header variant="h1" description={selected ? `계정 ${selected}` : "전체 계정 (통합)"}>리포트</Header>}>
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Executive Summary{selected ? ` — 계정 ${selected}` : " — 전체 계정"}</Header>}>
          <ColumnLayout columns={4} variant="text-grid">
            <Value label="분석 계정">{s.accounts}</Value>
            <Value label="Principal">{s.principals.toLocaleString()}</Value>
            <Value label="Persona">{s.personas}</Value>
            <Value label="제거된 미사용 권한">{s.unused_permissions_removed.toLocaleString()}</Value>
          </ColumnLayout>
        </Container>

        {/* 전체 뷰 + 계정별 분해가 있으면 계정별 요약 표(먼저 계정별로 구분해 보여줌). */}
        {!selected && s.by_account && s.by_account.length > 0 && (
          <Table
            variant="container"
            header={<Header variant="h2">계정별 요약</Header>}
            columnDefinitions={[
              { id: "acct", header: "계정", cell: (a: ExecSummary) => a.account_id },
              { id: "principals", header: "Principal", cell: (a: ExecSummary) => a.principals.toLocaleString() },
              { id: "personas", header: "Persona", cell: (a: ExecSummary) => a.personas },
              { id: "unused", header: "미사용 권한", cell: (a: ExecSummary) => a.unused_permissions_removed.toLocaleString() },
            ]}
            items={s.by_account}
          />
        )}

        <Container header={<Header variant="h2">산출물 다운로드{selected ? ` (계정 ${selected})` : " (전체)"}</Header>}>
          <SpaceBetween size="s">
            <SpaceBetween direction="horizontal" size="s">
              <Button iconName="external" onClick={() => window.open(data.report_html_url, "_blank")}>리포트 HTML 보기</Button>
              <Button iconName="download" onClick={() => handleDownload(data.report_html_url, `report_${data.run_id}${selected ? "_" + selected : ""}.html`)}>HTML 다운로드</Button>
              <Button iconName="download" onClick={() => handleDownload(data.iac_zip_url, `permission_sets_${data.run_id}.tf`)}>Terraform 다운로드</Button>
            </SpaceBetween>
            {downloadError && (
              <Alert type="error" dismissible onDismiss={() => setDownloadError(null)}
                header="다운로드 실패">
                {downloadError}
              </Alert>
            )}
          </SpaceBetween>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
