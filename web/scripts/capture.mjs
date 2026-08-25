import { chromium } from "@playwright/test";
import { mkdirSync } from "node:fs";

const BASE = "http://localhost:5173";
const OUT = "/home/dakota/projects/Proof/.impeccable/review";
const routes = [
  ["overview", "/overview"],
  ["changesets", "/changesets"],
  ["changeset-detail", "/changesets/cs-01j9x85rfq7h3n20"],
  ["changeset-rejected", "/changesets/cs-01j9x77bwz2d6s48"],
  ["objects", "/objects"],
  ["releases", "/releases"],
  ["release-detail", "/releases/rel-01j9x71dlm6p3x42"],
  ["proofs", "/proofs"],
  ["authority", "/authority"],
];

mkdirSync(OUT, { recursive: true });
const browser = await chromium.launch();

for (const [w, width, height] of [
  ["desktop", 1440, 900],
  ["mobile", 390, 844],
]) {
  const context = await browser.newContext({
    viewport: { width, height },
    deviceScaleFactor: 2,
  });
  const page = await context.newPage();
  for (const [name, path] of routes) {
    try {
      await page.goto(BASE + path, { waitUntil: "commit", timeout: 15_000 });
      await page.waitForTimeout(1200);
      await page.screenshot({
        path: `${OUT}/${name}-${w}.png`,
        fullPage: true,
      });
      console.log("ok", name, w);
    } catch (e) {
      console.log("FAIL", name, w, e.message.slice(0, 120));
    }
  }
  // command palette open state, desktop only
  if (w === "desktop") {
    await page.goto(BASE + "/overview", { waitUntil: "commit", timeout: 15_000 });
    // wait for hydration: the palette keydown listener only exists once React mounts
    await page.waitForSelector('[aria-label="Open command palette"]', {
      timeout: 15_000,
    });
    await page.keyboard.press("ControlOrMeta+k");
    await page.waitForSelector('[role="dialog"][aria-label="Command palette"]', {
      timeout: 5_000,
    });
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${OUT}/palette-desktop.png` });
  }
  await context.close();
}

await browser.close();
console.log("captured");
