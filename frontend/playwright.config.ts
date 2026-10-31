import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:4177",
    headless: true,
    launchOptions: {
      executablePath: process.env.CHROME_PATH || "/opt/google/chrome/chrome",
      args: ["--no-sandbox"],
    },
    // Do not retain screenshots/traces: contact fixtures must stay inside the test process.
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  webServer: {
    command: "npm run dev -- --port 4177 --strictPort",
    url: "http://127.0.0.1:4177",
    reuseExistingServer: false,
  },
});
