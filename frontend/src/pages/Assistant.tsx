import { useState, useRef, useEffect } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Button from "@cloudscape-design/components/button";
import Input from "@cloudscape-design/components/input";
import Alert from "@cloudscape-design/components/alert";
import Badge from "@cloudscape-design/components/badge";
import Spinner from "@cloudscape-design/components/spinner";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import { api } from "@/api/client";
import type { AssistantMessage } from "@/api/types";

const SUGGESTIONS = [
  "위험도 High 이상인 principal 은?",
  "상승 경로가 있는 역할을 알려줘",
  "장기 액세스키를 가진 사용자는?",
];

// 채팅 말풍선 — 사용자는 우측, assistant 는 좌측 정렬.
function Bubble({ side, children }: { side: "left" | "right"; children: React.ReactNode }) {
  const isUser = side === "right";
  return (
    <div style={{ display: "flex", justifyContent: isUser ? "flex-end" : "flex-start" }}>
      <div
        style={{
          maxWidth: "78%",
          borderRadius: 12,
          padding: "10px 14px",
          // Cloudscape 토큰 대신 최소한의 표면 구분만 — 다크 토큰과 조화되는 반투명.
          background: isUser ? "rgba(57,135,229,0.18)" : "rgba(255,255,255,0.06)",
          border: "1px solid rgba(255,255,255,0.08)",
        }}
      >
        {children}
      </div>
    </div>
  );
}

export default function Assistant() {
  const [messages, setMessages] = useState<AssistantMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [aiEnabled, setAiEnabled] = useState<boolean | null>(null); // null=로딩중
  const scrollRef = useRef<HTMLDivElement>(null);

  // AI 개입 기능 활성 여부(대시보드 토글). 꺼져 있으면 입력 비활성 + 안내.
  useEffect(() => {
    api.getAiSettings().then((s) => setAiEnabled(s.enabled)).catch(() => setAiEnabled(false));
  }, []);

  // 새 메시지마다 대화 영역 하단으로 스크롤.
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  async function ask(question: string) {
    if (!question.trim() || busy) return;
    setMessages((m) => [...m, { role: "user", text: question }]);
    setInput("");
    setBusy(true);
    const answer = await api.askAssistant(question);
    setMessages((m) => [...m, { role: "assistant", text: answer.answer, answer }]);
    setBusy(false);
  }

  return (
    <ContentLayout header={<Header variant="h1" description="수집·정규화 데이터에 grounding 된 답변만 반환. 근거 없는 사실은 거부됩니다.">Assistant</Header>}>
      <Container disableContentPaddings>
        <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 260px)", minHeight: 420 }}>
          {/* 스크롤 대화 영역 */}
          <div ref={scrollRef} style={{ flex: 1, overflowY: "auto", padding: 20 }}>
            <SpaceBetween size="m">
              {aiEnabled === false && (
                <Alert type="warning" header="AI 기능이 꺼져 있습니다">
                  AI 어시스턴트는 현재 비활성 상태입니다. 대시보드 상단의 <b>AI 기능</b> 토글을 켜면 사용할 수 있습니다.
                  (카탈로그·조치 필요 항목·리포트는 AI 없이 그대로 이용 가능합니다.)
                </Alert>
              )}
              {messages.length === 0 && aiEnabled !== false && (
                <SpaceBetween size="s">
                  <Box color="text-body-secondary">IAM 최소권한에 대해 물어보세요. 예시:</Box>
                  <SpaceBetween direction="horizontal" size="xs">
                    {SUGGESTIONS.map((s) => (
                      <Button key={s} onClick={() => ask(s)}>{s}</Button>
                    ))}
                  </SpaceBetween>
                </SpaceBetween>
              )}

              {messages.map((m, i) =>
                m.role === "user" ? (
                  <Bubble key={i} side="right"><Box>{m.text}</Box></Bubble>
                ) : (
                  <Bubble key={i} side="left">
                    <SpaceBetween size="xs">
                      <SpaceBetween direction="horizontal" size="xs">
                        <Badge color="blue">✦ AI 제안—검증 필요</Badge>
                        {m.answer?.grounded && <Badge color="green">grounded</Badge>}
                      </SpaceBetween>
                      <Box>{m.text}</Box>
                      {m.answer && m.answer.citations.length > 0 && (
                        <ExpandableSection headerText={`근거 ${m.answer.citations.length}건`} variant="footer">
                          <SpaceBetween size="xxs">
                            {m.answer.citations.map((c, j) => (
                              <Box key={j} fontSize="body-s">
                                {c.principal ?? ""} {c.action ? `· ${c.action}` : ""} — <i>{c.source}</i>
                              </Box>
                            ))}
                          </SpaceBetween>
                        </ExpandableSection>
                      )}
                    </SpaceBetween>
                  </Bubble>
                ),
              )}

              {busy && <Bubble side="left"><Box><Spinner /> 답변 생성 중…</Box></Bubble>}
            </SpaceBetween>
          </div>

          {/* 하단 고정 입력창 */}
          <div style={{ borderTop: "1px solid rgba(255,255,255,0.1)", padding: 16 }}>
            <SpaceBetween size="xs">
              <div style={{ display: "flex", gap: 8 }}>
                <div style={{ flex: 1 }}>
                  <Input
                    value={input}
                    placeholder={aiEnabled === false ? "AI 기능이 꺼져 있습니다" : "질문을 입력하세요…"}
                    disabled={aiEnabled === false}
                    onChange={(e) => setInput(e.detail.value)}
                    onKeyDown={(e) => e.detail.key === "Enter" && ask(input)}
                  />
                </div>
                <Button variant="primary" onClick={() => ask(input)} disabled={busy || aiEnabled === false} loading={busy}>전송</Button>
              </div>
              <Alert type="info">답변은 AI 제안이며, 표시된 근거(grounding 출처)로 검증 후 사용하세요.</Alert>
            </SpaceBetween>
          </div>
        </div>
      </Container>
    </ContentLayout>
  );
}
