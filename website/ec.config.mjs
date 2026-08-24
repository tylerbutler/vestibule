export default {
  themes: ["catppuccin-latte", "catppuccin-mocha"],
  themeCssSelector: (theme) =>
    theme.type === "dark" ? '[data-theme="dark"]' : '[data-theme="light"]',
  styleOverrides: {
    borderRadius: "0.875rem",
    frames: {
      shadowColor: "transparent"
    }
  }
};
