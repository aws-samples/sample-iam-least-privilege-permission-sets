import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { applyMode, Mode } from "@cloudscape-design/global-styles";
import "@cloudscape-design/global-styles/index.css";
import App from "./App";

// UI 껍데기 = Cloudscape 기본 다크 토큰(자동 적용). 커스텀 hex 없음.
applyMode(Mode.Dark);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);
