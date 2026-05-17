const { test, expect } = require('@playwright/test');

test.describe.serial('setup and login flows', () => {
  const username = 'admin';
  const password = 'StrongPass1234';

  async function signIn(page) {
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL('http://127.0.0.1:8080/');
    await expect(page.locator('#logout-btn')).toBeVisible();
  }

  async function fulfillJson(route, payload) {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(payload),
    });
  }

  async function stubDashboardApi(page, getServers) {
    await page.route('**/api/servers', route => fulfillJson(route, getServers()));
    await page.route('**/api/keys/global', route => fulfillJson(route, { has_key: false }));
    await page.route('**/api/audit-events*', route => fulfillJson(route, { items: [] }));
    await page.route('**/api/observability/summary*', route => fulfillJson(route, { totals: { updates_total: 0, success_rate_pct: 0 } }));
    await page.route('**/api/update-policies', route => fulfillJson(route, []));
    await page.route('**/api/dashboard/summary*', route => fulfillJson(route, { servers: [] }));
  }

  function makeServer(name, status = 'idle', pendingUpdates = []) {
    return {
      name,
      host: `${name}.example.test`,
      port: 22,
      user: 'root',
      status,
      tags: [],
      pending_updates: pendingUpdates,
      pending_package_count: pendingUpdates.length,
      security_update_count: pendingUpdates.filter(update => update.security).length,
      logs: 'ready',
    };
  }

  function makePendingUpdates(count) {
    return Array.from({ length: count }, (_, index) => ({
      package: `pkg-${String(index + 1).padStart(2, '0')}`,
      current_version: '1.0.0',
      candidate_version: '1.0.1',
      source: 'ubuntu',
      security: index % 3 === 0,
      cve_state: index % 2 === 0 ? 'pending' : 'ready',
      cves: index % 5 === 0 ? [`CVE-2026-${String(index + 1).padStart(4, '0')}`] : [],
    }));
  }

  test('setup form shows mismatch error', async ({ page }) => {
    await page.goto('/setup');
    if (!/\/setup$/.test(page.url())) {
      test.skip(true, 'setup already completed');
    }
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.locator('#password-confirm').fill('DifferentPass1234');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page.locator('#error-banner')).toBeVisible();
    await expect(page.locator('#error-banner')).toContainText('Passwords do not match.');
    await expect(page).toHaveURL(/\/setup$/);
  });

  test('setup creates account and redirects to status page', async ({ page }) => {
    await page.goto('/setup');
    if (/\/login$/.test(page.url())) {
      await signIn(page);
      return;
    }
    if (page.url() === 'http://127.0.0.1:8080/') {
      await expect(page.locator('#logout-btn')).toBeVisible();
      return;
    }
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.locator('#password-confirm').fill(password);
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL('http://127.0.0.1:8080/');
    await expect(page.locator('#logout-btn')).toBeVisible();
  });

  test('invalid login shows error, valid login succeeds', async ({ page }) => {
    await page.goto('/login');
    await expect(page).toHaveURL(/\/login$/);

    await page.locator('#username').fill(username);
    await page.locator('#password').fill('WrongPassword123');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.locator('#error-banner')).toBeVisible();
    await expect(page.locator('#error-banner')).toContainText(/invalid credentials|login failed/i);
    await expect(page).toHaveURL(/\/login$/);

    await page.locator('#password').fill(password);
    await signIn(page);
  });

  test('pending updates drawer keeps scroll position after server refresh', async ({ page }) => {
    let servers = [makeServer('demo-host', 'pending_approval', makePendingUpdates(80))];
    await stubDashboardApi(page, () => servers);

    await page.goto('/login');
    await signIn(page);

    await page.locator('#servers-table tbody button[data-action="open-drawer"][data-tab="pending"]').click();
    const pendingPanel = page.locator('#drawer-panel-pending');
    await expect(pendingPanel).toHaveClass(/active/);
    await expect(pendingPanel.locator('tbody tr')).toHaveCount(80);

    await pendingPanel.evaluate(el => { el.scrollTop = 520; });
    const beforeRefresh = await pendingPanel.evaluate(el => el.scrollTop);
    expect(beforeRefresh).toBeGreaterThan(0);

    servers = [makeServer('demo-host', 'pending_approval', makePendingUpdates(80).map(update => ({ ...update, cve_state: 'ready' })))];
    await page.evaluate(() => window.fetchServers());

    await expect.poll(() => pendingPanel.evaluate(el => el.scrollTop)).toBeGreaterThanOrEqual(beforeRefresh - 1);
  });

  test('auto refresh defers table replacement while an update action is being clicked', async ({ page }) => {
    let servers = [makeServer('demo-host')];
    let updateRequests = 0;
    await stubDashboardApi(page, () => servers);
    await page.route('**/api/update/demo-host', route => {
      updateRequests += 1;
      return fulfillJson(route, { ok: true });
    });

    await page.goto('/login');
    await signIn(page);

    const updateButton = page.locator('#servers-table tbody button[data-action="update-server"][data-name="demo-host"]');
    await expect(updateButton).toBeVisible();
    const updateButtonHandle = await updateButton.elementHandle();
    expect(updateButtonHandle).not.toBeNull();

    await updateButtonHandle.dispatchEvent('pointerdown', {
      pointerId: 1,
      pointerType: 'mouse',
      isPrimary: true,
      bubbles: true,
      cancelable: true,
    });

    servers = [makeServer('renamed-host')];
    await page.evaluate(() => window.fetchServers());
    await expect(page.locator('#servers-table tbody tr[data-name="demo-host"]')).toBeVisible();

    await updateButtonHandle.dispatchEvent('pointerup', {
      pointerId: 1,
      pointerType: 'mouse',
      isPrimary: true,
      bubbles: true,
      cancelable: true,
    });
    await updateButtonHandle.dispatchEvent('click', { bubbles: true, cancelable: true });

    await expect.poll(() => updateRequests).toBe(1);
  });

  test('auto refresh resumes when an action press loses page focus', async ({ page }) => {
    let servers = [makeServer('demo-host')];
    await stubDashboardApi(page, () => servers);

    await page.goto('/login');
    await signIn(page);

    const updateButton = page.locator('#servers-table tbody button[data-action="update-server"][data-name="demo-host"]');
    await expect(updateButton).toBeVisible();
    const updateButtonHandle = await updateButton.elementHandle();
    expect(updateButtonHandle).not.toBeNull();

    await updateButtonHandle.dispatchEvent('pointerdown', {
      pointerId: 1,
      pointerType: 'mouse',
      isPrimary: true,
      bubbles: true,
      cancelable: true,
    });

    servers = [makeServer('renamed-host')];
    await page.evaluate(() => window.fetchServers());
    await expect(page.locator('#servers-table tbody tr[data-name="demo-host"]')).toBeVisible();

    await page.evaluate(() => window.dispatchEvent(new Event('blur')));

    await expect(page.locator('#servers-table tbody tr[data-name="renamed-host"]')).toBeVisible();
  });
});
