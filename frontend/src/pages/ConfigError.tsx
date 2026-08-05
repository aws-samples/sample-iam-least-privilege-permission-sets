// Rendered when a non-mock build is missing Cognito configuration (fail-closed auth gate).
// The app must not load without an authentication backend, so we show a clear configuration error
// instead of silently bypassing auth.
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";

export default function ConfigError() {
  return (
    <div style={{ maxWidth: 640, margin: "10vh auto", padding: "0 16px" }}>
      <Container header={<Header variant="h1">LP2PS — Configuration Error</Header>}>
        <SpaceBetween size="m">
          <Alert type="error" header="Authentication is not configured">
            Cognito user pool details were not injected at build time. Set the following environment
            variables before <code>npm run build</code>:
          </Alert>
          <Box variant="code">
            VITE_COGNITO_USER_POOL_ID
            <br />
            VITE_COGNITO_CLIENT_ID
          </Box>
          <Box color="text-body-secondary">
            (infra/scripts/deploy-all.sh injects these automatically.)
          </Box>
        </SpaceBetween>
      </Container>
    </div>
  );
}
