import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
// The design system. `styles.css` owns the `:root` custom properties that
// `lib/tokens.ts` reads as `var(--x)`, plus every state-dependent rule an
// inline style cannot express (:hover, :focus-visible, aria-selected,
// keyframes, prefers-reduced-motion). It was never imported here, which is why
// the stylesheet was dead: alert rows had no hover state, focus rings never
// appeared, and the reduced-motion branch never applied.
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
