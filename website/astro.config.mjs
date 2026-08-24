import { defineConfig } from "astro/config";
import expressiveCode from "astro-expressive-code";
import mdx from "@astrojs/mdx";

export default defineConfig({
  integrations: [
    expressiveCode(),
    mdx()
  ],
  output: "static"
});
