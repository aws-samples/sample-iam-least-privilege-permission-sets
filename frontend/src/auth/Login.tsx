// Cognito SRP 로그인 화면. 미인증 시 App 대신 렌더된다(mock 모드에선 우회).
import { useState } from "react";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import Form from "@cloudscape-design/components/form";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import Input from "@cloudscape-design/components/input";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { signIn } from "./cognito";

export default function Login({ onSignedIn }: { onSignedIn: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await signIn(email.trim(), password);
      onSignedIn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "로그인 실패");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: "10vh auto", padding: "0 16px" }}>
      <Container header={<Header variant="h1">LP2PS 로그인</Header>}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Form
            actions={
              <Button variant="primary" loading={busy} formAction="submit">
                로그인
              </Button>
            }
          >
            <SpaceBetween size="m">
              {error && <Alert type="error">{error}</Alert>}
              <FormField label="이메일">
                <Input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.detail.value)}
                  autoFocus
                />
              </FormField>
              <FormField label="비밀번호">
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.detail.value)}
                />
              </FormField>
              <Box color="text-status-inactive" fontSize="body-s">
                IAM Identity Center / Cognito 자격증명으로 로그인합니다.
                {/* 토큰을 메모리에만 보관하므로(auth/inMemoryStorage.ts — XSS 탈취 노출 축소)
                    페이지를 새로고침하면 세션이 사라진다. 예상 동작임을 미리 알린다. */}
                <br />
                보안상 토큰을 브라우저 저장소에 남기지 않으므로, 페이지를 새로고침하면 다시 로그인해야 합니다.
              </Box>
            </SpaceBetween>
          </Form>
        </form>
      </Container>
    </div>
  );
}
