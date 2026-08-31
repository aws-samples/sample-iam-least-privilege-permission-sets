// AppLayout 의 SplitPanel 슬롯을 라우트 페이지가 쓸 수 있게 열어주는 컨텍스트.
//
// 왜 컨텍스트인가: `splitPanel` 은 `AppLayout`(App.tsx) 의 prop 이고 슬롯이 **하나뿐**이다. 반면
// 패널 내용을 아는 쪽은 라우트 자식(PersonaReview)이다. prop 으로 내리려면 App 이 모든 페이지의
// 패널 상태를 알아야 하므로, 자식이 등록하고 App 이 렌더하는 방향으로 뒤집는다.
//
// 슬롯이 하나라는 제약이 UI 설계를 결정한다 — "적용 대상"과 "정책 편집"을 각각 다른 패널로 띄울 수
// 없으므로 한 패널 안의 Tabs 로 넣는다.
import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";

interface SplitPanelState {
  /** 패널 본문(없으면 AppLayout 에 splitPanel 을 넘기지 않아 토글 버튼도 안 보인다). */
  content: ReactNode | null;
  header: string;
  open: boolean;
  // 🔴 setPanel/setOpen 은 **렌더 간 동일 참조**여야 한다. 등록하는 쪽(PersonaReview)이 이 함수를
  // useEffect/useCallback 의존성에 넣기 때문에, 매 렌더 새로 만들면 다음 루프가 돈다:
  //   setPanel(새 element) → provider state 변경 → 컨텍스트 값 재생성 → 소비자 콜백 identity 변경
  //   → 등록 effect 재실행 → setPanel(또 새 element) → …  (React "Maximum update depth exceeded")
  // 실제로 이 루프를 만들었고 헤드리스 클릭 검증에서 잡혔다. useState setter 만 호출하므로
  // useCallback([]) 로 고정할 수 있다.
  setPanel: (panel: { header: string; content: ReactNode } | null) => void;
  setOpen: (open: boolean) => void;
}

const Ctx = createContext<SplitPanelState | null>(null);

export function SplitPanelProvider({ children }: { children: ReactNode }) {
  const [content, setContent] = useState<ReactNode | null>(null);
  const [header, setHeader] = useState("");
  const [open, setOpen] = useState(false);

  const setPanel = useCallback((panel: { header: string; content: ReactNode } | null) => {
    if (panel === null) {
      setContent(null);
      setOpen(false);
      return;
    }
    setHeader(panel.header);
    setContent(panel.content);
  }, []);

  const value = useMemo<SplitPanelState>(
    () => ({ content, header, open, setPanel, setOpen }),
    [content, header, open, setPanel],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** 페이지에서 우측 슬라이드 패널을 등록·개폐한다. Provider 밖에서 부르면 즉시 실패(조용한 무동작 금지). */
export function useSplitPanel(): SplitPanelState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useSplitPanel 은 SplitPanelProvider 안에서만 사용할 수 있습니다.");
  return ctx;
}
