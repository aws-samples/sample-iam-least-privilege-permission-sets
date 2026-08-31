import { useEffect, useState } from "react";
import { Routes, Route, useNavigate, useLocation, Navigate } from "react-router-dom";
import AppLayout from "@cloudscape-design/components/app-layout";
import SideNavigation from "@cloudscape-design/components/side-navigation";
import TopNavigation from "@cloudscape-design/components/top-navigation";
import Flashbar from "@cloudscape-design/components/flashbar";
import Spinner from "@cloudscape-design/components/spinner";
import Box from "@cloudscape-design/components/box";
import { USING_MOCKS } from "@/api/client";
import { cognitoConfigured, getIdToken, signOut } from "@/auth/cognito";
import SplitPanel from "@cloudscape-design/components/split-panel";
import { AccountProvider, useAccounts } from "@/AccountContext";
import { SplitPanelProvider, useSplitPanel } from "@/SplitPanelContext";
import Login from "@/auth/Login";

import Dashboard from "@/pages/Dashboard";
import PersonaReview from "@/pages/PersonaReview";
import CleanupBacklog from "@/pages/CleanupBacklog";
import Reports from "@/pages/Reports";
import Assistant from "@/pages/Assistant";
import Runs from "@/pages/Runs";
import ConfigError from "@/pages/ConfigError";

// Region shown in the top nav. Falls back to a neutral placeholder rather than a specific region so a
// misbuilt bundle cannot claim the wrong one.
const DEPLOY_REGION = import.meta.env.VITE_AWS_REGION || "—";

const NAV_ITEMS = [
  { type: "link" as const, text: "대시보드", href: "/dashboard" },
  { type: "link" as const, text: "Persona 검토", href: "/personas" },
  { type: "link" as const, text: "조치 필요 항목", href: "/cleanup" },
  { type: "link" as const, text: "리포트", href: "/reports" },
  { type: "link" as const, text: "Assistant", href: "/assistant" },
  { type: "divider" as const },
  { type: "link" as const, text: "실행 이력", href: "/runs" },
];

// Auth gate: USING_MOCKS (dev mock) bypasses. A non-mock build with Cognito unconfigured renders
// ConfigError (fail-closed). Otherwise a valid token is required.
export default function App() {
  // fail-closed: a real (non-mock) build must have a configured auth backend. Never bypass on misconfig.
  const configError = !USING_MOCKS && !cognitoConfigured;
  // Login state: null=checking, false=unauthenticated, true=authenticated. Mock mode passes immediately.
  const bypass = USING_MOCKS;
  const [authed, setAuthed] = useState<boolean | null>(bypass ? true : null);

  useEffect(() => {
    if (bypass || configError) return;
    void getIdToken().then((t) => setAuthed(t !== null));
  }, [bypass, configError]);

  if (configError) {
    return <ConfigError />;
  }
  if (authed === null) {
    return (
      <Box textAlign="center" padding="xxl">
        <Spinner size="large" /> Checking authentication…
      </Box>
    );
  }
  if (!authed) {
    return <Login onSignedIn={() => setAuthed(true)} />;
  }
  return (
    <AccountProvider>
      <SplitPanelProvider>
        <Shell onSignOut={() => { signOut(); setAuthed(false); }} />
      </SplitPanelProvider>
    </AccountProvider>
  );
}

function Shell({ onSignOut }: { onSignOut: () => void }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { accounts, selected, setSelected } = useAccounts();
  const panel = useSplitPanel();

  // 계정 선택기: "전체 계정"(통합) + 계정별. 관제 계정을 골라도 전체가 기본이므로 "전체"가 첫 항목.
  // Cloudscape menu-dropdown 은 빈 문자열 id 를 안정적으로 전달하지 못하므로 "__all__" 센티넬 사용.
  const ALL = "__all__";
  const accountLabel = selected === "" ? `전체 계정 (${accounts.length || "…"})` : `계정 ${selected}`;
  const accountItems = [
    { id: ALL, text: "전체 계정 (통합)" },
    ...accounts.map((a) => ({
      id: a.account_id,
      text: `${a.account_id}${a.is_tooling ? " · 관제" : ""} · ${a.status}`,
    })),
  ];

  return (
    <>
      <div id="top-nav">
        <TopNavigation
          identity={{
            href: "/dashboard",
            title: "LP2PS — IAM 최소권한 → Permission Set",
            // SPA 라우팅으로 처리한다. 기본 앵커 동작(전체 페이지 로드)을 그대로 두면 토큰을
            // 브라우저 저장소에 남기지 않는 설계상 제목을 클릭하는 순간 로그아웃된다.
            // 아래 SideNavigation 의 onFollow 와 같은 처리.
            onFollow: (e) => {
              e.preventDefault();
              navigate("/dashboard");
            },
          }}
          utilities={[
            {
              type: "menu-dropdown",
              text: accountLabel,
              iconName: "multiscreen",
              items: accountItems,
              onItemClick: (e) => setSelected(e.detail.id === ALL ? "" : e.detail.id),
            },
            // Deployment region label. Injected at build time from the config's `region:`
            // (build-web.sh), never hardcoded -- a literal here would show the wrong region to
            // every customer who deploys elsewhere.
            { type: "button", text: DEPLOY_REGION },
            ...(USING_MOCKS
              ? []
              : [{ type: "button" as const, text: "로그아웃", iconName: "external" as const, onClick: onSignOut }]),
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#top-nav"
        toolsHide
        // 우측 슬라이드 패널. 페이지가 SplitPanelContext 로 내용을 등록하면 여기서 렌더된다.
        // content 가 null 이면 prop 을 아예 넘기지 않는다 — 넘기면 내용이 없는데도 하단에 빈
        // 패널 토글 바가 남는다.
        splitPanelOpen={panel.open}
        onSplitPanelToggle={(e) => panel.setOpen(e.detail.open)}
        // position="side" 고정: 아래(bottom)에 붙으면 "하단에 나와서 불편하다"는 원래 문제로 돌아간다.
        splitPanelPreferences={{ position: "side" }}
        splitPanel={
          panel.content ? (
            <SplitPanel
              header={panel.header}
              hidePreferencesButton
              i18nStrings={{
                closeButtonAriaLabel: "패널 닫기",
                openButtonAriaLabel: "패널 열기",
                resizeHandleAriaLabel: "패널 크기 조절",
                preferencesTitle: "분할 패널 설정",
                preferencesPositionLabel: "패널 위치",
                preferencesPositionDescription: "패널을 화면 아래 또는 옆에 배치합니다.",
                preferencesPositionSide: "옆",
                preferencesPositionBottom: "아래",
                preferencesConfirm: "확인",
                preferencesCancel: "취소",
              }}
            >
              {panel.content}
            </SplitPanel>
          ) : undefined
        }
        navigation={
          <SideNavigation
            activeHref={location.pathname}
            header={{ href: "/dashboard", text: "LP2PS" }}
            items={NAV_ITEMS}
            onFollow={(e) => {
              if (!e.detail.external) {
                e.preventDefault();
                navigate(e.detail.href);
              }
            }}
          />
        }
        notifications={
          USING_MOCKS ? (
            <Flashbar
              items={[
                {
                  type: "info",
                  header: "목데이터 모드",
                  content:
                    "VITE_USE_MOCKS=true — 모든 화면이 목데이터로 동작합니다. 플래그를 끄면 실 API로 전환됩니다.",
                  dismissible: false,
                },
              ]}
            />
          ) : undefined
        }
        content={
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/personas" element={<PersonaReview />} />
            <Route path="/cleanup" element={<CleanupBacklog />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/assistant" element={<Assistant />} />
            <Route path="/runs" element={<Runs />} />
          </Routes>
        }
      />
    </>
  );
}
