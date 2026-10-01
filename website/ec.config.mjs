export default {
  themes: ["catppuccin-latte", "catppuccin-mocha"],
  themeCssSelector: (theme) =>
    theme.type === "dark" ? '[data-theme="dark"]' : '[data-theme="light"]',
  styleOverrides: {
    borderRadius: "0.875rem",
    codeFontFamily: '"Geist Mono", ui-monospace, monospace',
    frames: {
      shadowColor: "transparent"
    }
  }
};
