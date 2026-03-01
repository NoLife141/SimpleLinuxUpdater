const { test, expect } = require('@playwright/test');

test.describe.serial('setup and login flows', () => {
  const username = 'admin';
  const password = 'StrongPass1234';

  test('setup form shows mismatch error', async ({ page }) => {
    await page.goto('/setup');
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
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL('http://127.0.0.1:8080/');
    await expect(page.locator('#logout-btn')).toBeVisible();
  });
});
