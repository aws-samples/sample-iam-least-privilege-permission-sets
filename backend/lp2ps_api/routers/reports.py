"""GET /reports/{run_id} — presigned S3 URL(report.html) + exec summary.

account 쿼리 파라미터를 주면 계정별 리포트(report-<account>.html) + 계정별 exec_summary 를 반환한다.
전체(account 미지정)면 통합 리포트. 엔진이 계정별 report-<account>.html 을 미리 생성한다.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException

from lp2ps.models import ExecSummary, ReportRef

from ..deps import valid_run_id
from . import get_repos

router = APIRouter(tags=["reports"])

_ACCOUNT_RE = re.compile(r"^\d{12}$")  # AWS account id 12자리


@router.get("/reports")
def get_latest_report(account: str | None = None) -> ReportRef | None:
    """최신 run 의 리포트. account 지정 시 그 계정 리포트, 없으면 전체 통합.

    (기존엔 프론트가 하드코딩된 run_id 를 넘겨 실 API 에서 404→무한로딩 됐다.)

    **리포트가 아직 없으면 404 가 아니라 200 + null 이다.** 이 endpoint 는 특정 리소스 조회가
    아니라 "지금 볼 수 있는 최신 리포트가 있나"를 묻는 질의이고, '아직 없음'은 갓 배포한 고객의
    **정상 상태**다(형제 endpoint 인 /catalog·/cleanup-backlog·/accounts·/metrics 는 모두 이
    상태에서 200 + 빈 목록을 준다 — 유일하게 여기만 404 를 던져 화면에 붉은 오류로 보였다).
    특정 run 을 지목하는 GET /reports/{run_id} 는 그대로 404 다 — 그건 진짜 not-found 다.

    null 이 되는 두 경우:
      (a) 완료된 run 이 없다 — 아직 전체 조회를 한 번도 돌리지 않았다.
      (b) 완료된 run 은 있는데 exec_summary.json 이 없다 — 예: collect 단계에서 실패해 산출물을
          남기지 못한 run. 실패 자체는 실행 이력 화면의 status 로 드러나므로 여기서 오류로
          위장하지 않는다.
    """
    repos = get_repos()
    run_id = repos.latest_run_id()
    if not run_id or not repos.run_artifact_exists(run_id, "exec_summary.json"):
        return None
    return _build_report(run_id, account)


@router.get("/reports/{run_id}")
def get_report(run_id: str, account: str | None = None) -> ReportRef:
    if not valid_run_id(run_id):
        raise HTTPException(status_code=400, detail="잘못된 run_id 형식")
    return _build_report(run_id, account)


def _build_report(run_id: str, account: str | None) -> ReportRef:
    repos = get_repos()
    if not repos.run_artifact_exists(run_id, "exec_summary.json"):
        raise HTTPException(status_code=404, detail=f"리포트 없음: {run_id}")

    summary_raw = repos._storage(run_id).read_json("exec_summary.json")
    full = ExecSummary.model_validate(summary_raw)

    if account:
        if not _ACCOUNT_RE.match(account):
            raise HTTPException(status_code=400, detail="잘못된 account 형식")
        # 계정별 exec_summary + 계정별 report html. 계정별 리포트가 없으면(단일계정 run 등) 전체로 폴백.
        acct_summary = next((b for b in full.by_account if b.account_id == account), None)
        report_key = f"report-{account}.html"
        if acct_summary is not None and repos.run_artifact_exists(run_id, report_key):
            return ReportRef(
                run_id=run_id,
                report_html_url=repos.presign(run_id, report_key),
                iac_zip_url=repos.presign(run_id, "iac/permission_sets.tf"),
                exec_summary=acct_summary,
            )
        # 폴백: 계정별 산출물 없음 → 전체 리포트.

    return ReportRef(
        run_id=run_id,
        report_html_url=repos.presign(run_id, "report.html"),
        iac_zip_url=repos.presign(run_id, "iac/permission_sets.tf"),  # 후속: zip 번들로 교체
        exec_summary=full,
    )
