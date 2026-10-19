import {test as base, expect, type Page} from '@playwright/test';

//1. Describe what each fixture gives the test
type AuthFixtures = {
    adminPage: Page;
    hrPage: Page;
    employeePage: Page;
    employeeToken: string;
};

//2. Extend the built-in test with our own fixtures
export const test = base.extend<AuthFixtures>({
  adminPage: async ({ browser }, use) => {
    const context = await browser.newContext({ storageState: 'playwright/.auth/admin.json' });
    await use(await context.newPage());   // the test runs here
    await context.close();                // clean-up, after the test
  },

  hrPage: async ({ browser }, use) => {
    const context = await browser.newContext({ storageState: 'playwright/.auth/hr.json' });
    await use(await context.newPage());
    await context.close();
  },

  employeePage: async ({ browser }, use) => {
    const context = await browser.newContext({ storageState: 'playwright/.auth/employee.json' });
    await use(await context.newPage());
    await context.close();
  },
   // A token for API checks: log in through the API, no browser needed
  employeeToken: async ({ request }, use) => {
    const response = await request.post('/api/login', {
      data: { username: 'emp.ram', password: 'Sajilo@123' },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    await use(body.token);
  },
});

export { expect };