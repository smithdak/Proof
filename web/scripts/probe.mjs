import { chromium } from "@playwright/test";

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
page.on("console", (m) => console.log("[console]", m.type(), m.text().slice(0, 200)));
page.on("pageerror", (e) => console.log("[pageerror]", e.message.slice(0, 300)));
page.on("requestfailed", (r) => console.log("[reqfail]", r.url().slice(0, 120), r.failure()?.errorText));
try {
  await page.goto("http://localhost:5173/authority", { waitUntil: "commit", timeout: 15000 });
  console.log("committed");
  await page.waitForTimeout(3000);
  const rootHtml = await page.evaluate(() => document.getElementById("root")?.innerHTML.length ?? -1);
  console.log("root html length:", rootHtml);
} catch (e) {
  console.log("GOTO FAILED:", e.message.slice(0, 200));
}
await browser.close();
