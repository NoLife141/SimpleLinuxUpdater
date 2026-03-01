const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  workers: process.env.CI ? 1 : undefined,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://127.0.0.1:8080',
    headless: true,
    trace: 'on-first-retry',
  },
  webServer: {
    command: 'go build -o webserver . && mkdir -p .tmp-e2e && rm -f .tmp-e2e/servers.db && : > .tmp-e2e/known_hosts && DEBIAN_UPDATER_DB_PATH=.tmp-e2e/servers.db DEBIAN_UPDATER_KNOWN_HOSTS=.tmp-e2e/known_hosts ./webserver',
    url: 'http://127.0.0.1:8080/login',
    timeout: 120_000,
    reuseExistingServer: false,
  },
});
