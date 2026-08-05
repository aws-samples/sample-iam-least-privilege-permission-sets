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
import { AccountProvider, useAccounts } from "@/AccountContext";
import Login from "@/auth/Login";

import Dashboard from "@/pages/Dashboard";
import PersonaReview from "@/pages/PersonaReview";
import CleanupBacklog from "@/pages/CleanupBacklog";
import Reports from "@/pages/Reports";
import Assistant from "@/pages/Assistant";
import Runs from "@/pages/Runs";
import ConfigError from "@/pages/ConfigError";

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
      <Shell onSignOut={() => { signOut(); setAuthed(false); }} />
    </AccountProvider>
  );
}

function Shell({ onSignOut }: { onSignOut: () => void }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { accounts, selected, setSelected } = useAccounts();

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
          identity={{ href: "/dashboard", title: "LP2PS — IAM 최소권한 → Permission Set" }}
          utilities={[
            {
              type: "menu-dropdown",
              text: accountLabel,
              iconName: "multiscreen",
              items: accountItems,
              onItemClick: (e) => setSelected(e.detail.id === ALL ? "" : e.detail.id),
            },
            { type: "button", text: "us-west-2" },
            ...(USING_MOCKS
              ? []
              : [{ type: "button" as const, text: "로그아웃", iconName: "external" as const, onClick: onSignOut }]),
          ]}
        />
      </div>
      <AppLayout
        headerSelector="#top-nav"
        toolsHide
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
