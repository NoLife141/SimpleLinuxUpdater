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

  async function ensureSignedIn(page) {
    await page.goto('/login');
    if (/\/login$/.test(page.url())) {
      await signIn(page);
      return;
    }
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

  async function stubAdminApi(page, state = {}) {
    await page.route('**/api/app-settings/timezone', async route => {
      if (route.request().method() === 'PUT') {
        state.timezoneSave = await route.request().postDataJSON();
      }
      return fulfillJson(route, {
        timezone: 'America/Toronto',
        resolved_timezone: 'America/Toronto',
        editable_timezone: state.timezoneSave?.timezone || 'America/Toronto',
      });
    });
    await page.route('**/api/auth/sessions', async route => {
      if (route.request().method() === 'DELETE') {
        state.sessionClearCount = (state.sessionClearCount || 0) + 1;
        return fulfillJson(route, { deleted: 2 });
      }
      return fulfillJson(route, { session_count: 2 });
    });
    await page.route('**/api/auth/password', async route => {
      state.passwordPayload = await route.request().postDataJSON();
      return fulfillJson(route, { ok: true });
    });
    await page.route('**/api/metrics/token', route => fulfillJson(route, { enabled: true, token: 'test-token' }));
    await page.route('**/api/backup/status', route => fulfillJson(route, {
      db_path: '/tmp/simplelinuxupdater.db',
      backup_supported: true,
      known_hosts_path: '/tmp/known_hosts',
    }));
    await page.route('**/api/backup/restore', async route => {
      state.restoreCount = (state.restoreCount || 0) + 1;
      return fulfillJson(route, { restored: true, sessions_invalidated: false });
    });
    await page.route('**/api/update-policies/settings', route => fulfillJson(route, {
      timezone: 'America/Toronto',
      resolved_timezone: 'America/Toronto',
      global_blackouts: [],
    }));
    await page.route('**/api/update-policies/runs?*', route => fulfillJson(route, {
      timezone: 'America/Toronto',
      items: [{
        id: 7,
        policy_name: 'Nightly security',
        server_name: 'srv-web-01',
        status: 'succeeded',
        summary: 'completed',
        job_id: 'job-report-1',
        scheduled_for_utc: '2026-05-17T06:00:00Z',
      }],
    }));
    await page.route('**/api/update-policies', async route => {
      if (route.request().method() === 'POST') {
        state.policyPayload = await route.request().postDataJSON();
        return fulfillJson(route, { id: 42, ...state.policyPayload, matched_servers: ['srv-web-01'] });
      }
      return fulfillJson(route, {
        timezone: 'America/Toronto',
        items: state.policies || [{
          id: 12,
          name: 'Nightly security',
          enabled: true,
          target_tag: 'prod',
          include_tags: ['web'],
          exclude_tags: ['hold'],
          target_servers: ['srv-web-01'],
          package_scope: 'security',
          execution_mode: 'approval_required',
          cadence_kind: 'daily',
          time_local: '02:00',
          weekdays: [],
          matched_servers: ['srv-web-01'],
        }],
      });
    });
    await page.route('**/api/update-policies/*', async route => {
      if (route.request().method() === 'DELETE') {
        state.policyDeleteCount = (state.policyDeleteCount || 0) + 1;
        return fulfillJson(route, { ok: true });
      }
      return route.fallback();
    });
  }

  async function stubManageApi(page, state = {}) {
    await page.route('**/api/servers', route => fulfillJson(route, state.servers || [makeServer('demo-host')]));
    await page.route('**/api/servers/*', async route => {
      if (route.request().method() === 'DELETE') {
        state.deleteServerCount = (state.deleteServerCount || 0) + 1;
        state.deletedServerUrl = route.request().url();
        return fulfillJson(route, { ok: true });
      }
      return route.fallback();
    });
    await page.route('**/api/keys/global', async route => {
      if (route.request().method() === 'DELETE') {
        state.clearGlobalKeyCount = (state.clearGlobalKeyCount || 0) + 1;
        return fulfillJson(route, { ok: true });
      }
      return fulfillJson(route, { has_key: true });
    });
    await page.route('**/api/audit-events/prune', async route => {
      state.auditPruneCount = (state.auditPruneCount || 0) + 1;
      return fulfillJson(route, { deleted: 3 });
    });
    await page.route('**/api/audit-events*', route => fulfillJson(route, {
      items: [{
        id: 55,
        created_at: '2026-05-17T12:00:00Z',
        actor: 'admin',
        action: 'server.delete',
        target_type: 'server',
        target_name: 'demo-host',
        status: 'success',
        message: 'Deleted server',
      }],
      total: 1,
      page: 1,
      page_size: 20,
    }));
    await page.route('**/api/update-policies', route => fulfillJson(route, {
      items: state.policies || [{
        id: 9,
        name: 'Prod security',
        target_tag: 'prod',
        include_tags: ['web'],
        exclude_tags: ['hold'],
        matched_servers: ['demo-host'],
      }],
    }));
    await page.route('**/api/update-policies/*/overrides', route => fulfillJson(route, { items: [] }));
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

  test('admin scheduled policy editor submits rich targeting fields and renders report links', async ({ page }) => {
    const state = {};
    await ensureSignedIn(page);
    await stubAdminApi(page, state);

    await page.goto('/admin');
    await expect(page.locator('#scheduled-policy-table tbody')).toContainText('Nightly security');
    await expect(page.locator('#scheduled-policy-table tbody')).toContainText('include web');
    await expect(page.locator('#scheduled-runs-table a[href="/api/reports/jobs/job-report-1"]')).toBeVisible();

    await page.locator('#policy-name').fill('Weekend prod');
    await page.locator('#policy-target-tag').fill('');
    await page.locator('#policy-include-tags').fill('prod, web, prod');
    await page.locator('#policy-exclude-tags').fill('hold, db');
    await page.locator('#policy-target-servers').fill('srv-web-01, srv-web-02');
    await page.locator('#policy-time-local').fill('03:45');
    await page.locator('#policy-execution-mode').selectOption('approval_required');
    await page.locator('#policy-approval-timeout').fill('90');
    await page.locator('#policy-package-scope').selectOption('security');
    await page.locator('#policy-save-btn').click();

    await expect.poll(() => state.policyPayload).toMatchObject({
      name: 'Weekend prod',
      target_tag: '',
      include_tags: ['prod', 'web'],
      exclude_tags: ['hold', 'db'],
      target_servers: ['srv-web-01', 'srv-web-02'],
      execution_mode: 'approval_required',
      approval_timeout_minutes: 90,
    });
  });

  test('admin typed confirmations gate restore and policy deletion', async ({ page }) => {
    const state = {};
    await ensureSignedIn(page);
    await stubAdminApi(page, state);

    await page.goto('/admin');
    await page.locator('#backup-restore-file').setInputFiles({
      name: 'backup.slubkp',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('fake-backup'),
    });
    await page.locator('#backup-restore-passphrase').fill('LongPassphrase123');
    await page.evaluate(() => { window.prompt = () => 'WRONG'; });
    await page.locator('#backup-restore-btn').click();
    await expect.poll(() => state.restoreCount || 0).toBe(0);

    await page.evaluate(() => { window.prompt = () => 'RESTORE'; window.alert = () => {}; });
    await page.locator('#backup-restore-file').setInputFiles({
      name: 'backup.slubkp',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('fake-backup'),
    });
    await page.locator('#backup-restore-passphrase').fill('LongPassphrase123');
    await page.locator('#backup-restore-btn').click();
    await expect.poll(() => state.restoreCount || 0).toBe(1);

    await page.evaluate(() => { window.prompt = () => 'WRONG'; });
    await page.locator('#scheduled-policy-table button[data-action="delete-policy"][data-id="12"]').click();
    await expect.poll(() => state.policyDeleteCount || 0).toBe(0);

    await page.evaluate(() => { window.prompt = () => 'Nightly security'; });
    await page.locator('#scheduled-policy-table button[data-action="delete-policy"][data-id="12"]').click();
    await expect.poll(() => state.policyDeleteCount || 0).toBe(1);
  });

  test('admin password change sends payload and session clear requires typed confirmation', async ({ page }) => {
    const state = {};
    await ensureSignedIn(page);
    await stubAdminApi(page, state);

    await page.goto('/admin');
    await expect(page.locator('#auth-session-status')).toContainText('2 server-side session');
    await page.locator('#auth-current-password').fill(password);
    await page.locator('#auth-new-password').fill('NewStrongPass123');
    await page.locator('#auth-confirm-password').fill('NewStrongPass123');
    await page.locator('#auth-password-save').click();
    await expect.poll(() => state.passwordPayload).toEqual({
      current_password: password,
      new_password: 'NewStrongPass123',
      confirm_password: 'NewStrongPass123',
    });
    await expect(page.locator('#auth-password-status')).toContainText('Password changed');

    await page.evaluate(() => { window.prompt = () => 'WRONG'; });
    await page.locator('#auth-sessions-clear').click();
    await expect.poll(() => state.sessionClearCount || 0).toBe(0);

    await page.evaluate(() => {
      window.prompt = () => 'LOGOUT ALL';
      window.location.assign = () => {};
    });
    await page.locator('#auth-sessions-clear').click();
    await expect.poll(() => state.sessionClearCount || 0).toBe(1);
  });

  test('manage typed confirmations gate destructive host and audit actions', async ({ page }) => {
    const state = {};
    await ensureSignedIn(page);
    await stubManageApi(page, state);

    await page.goto('/manage');
    await expect(page.locator('#manage-servers-table tbody')).toContainText('demo-host');
    await expect(page.locator('#audit-table a[href="/api/reports/audit/55"]')).toBeVisible();

    await page.evaluate(() => {
      window.alert = () => {};
      window.prompt = () => 'WRONG';
    });
    await page.locator('#manage-servers-table button[data-action="delete-server"][data-name="demo-host"]').click();
    await page.locator('#audit-prune').click();
    await page.locator('#clear-global-key-btn').click();
    await expect.poll(() => state.deleteServerCount || 0).toBe(0);
    await expect.poll(() => state.auditPruneCount || 0).toBe(0);
    await expect.poll(() => state.clearGlobalKeyCount || 0).toBe(0);

    await page.evaluate(() => { window.prompt = message => message.includes('Delete server') ? 'demo-host' : 'PRUNE'; });
    await page.locator('#manage-servers-table button[data-action="delete-server"][data-name="demo-host"]').click();
    await page.locator('#audit-prune').click();
    await expect.poll(() => state.deleteServerCount || 0).toBe(1);
    await expect.poll(() => state.auditPruneCount || 0).toBe(1);

    await page.evaluate(() => { window.prompt = () => 'CLEAR GLOBAL KEY'; });
    await page.locator('#clear-global-key-btn').click();
    await expect.poll(() => state.clearGlobalKeyCount || 0).toBe(1);
  });

  test('manage policy override list follows live tag edits', async ({ page }) => {
    const state = {
      servers: [{ ...makeServer('demo-host'), tags: ['prod'] }],
    };
    await ensureSignedIn(page);
    await stubManageApi(page, state);

    await page.goto('/manage');
    await page.locator('#manage-servers-table button[data-action="edit-server"][data-name="demo-host"]').click();
    const overrides = page.locator('#edit-policy-overrides');
    await expect(overrides).toContainText('Disable "Prod security"');

    await page.locator('#edit-tags').fill('hold');
    await expect(overrides).toContainText('No tag-based scheduled policies currently match this server.');

    await page.locator('#edit-tags').fill('web');
    await expect(overrides).toContainText('Disable "Prod security"');

    state.policies = [{
      id: 10,
      name: 'Explicit server policy',
      target_tag: '',
      include_tags: [],
      exclude_tags: [],
      target_servers: ['demo-host'],
      matched_servers: ['Demo-Host'],
    }];
    state.servers = [{ ...makeServer('Demo-Host'), tags: ['misc'] }];

    await page.locator('#edit-cancel').click();
    await page.goto('/manage');
    await page.locator('#manage-servers-table button[data-action="edit-server"][data-name="Demo-Host"]').click();
    await expect(page.locator('#edit-policy-overrides')).toContainText('Disable "Explicit server policy"');
  });
});
