import { getSettings, normalizeBaseUrl, saveSettings } from "./shared.js";

const form = document.querySelector("[data-settings-form]");
const status = document.querySelector("[data-status]");

async function init() {
  const settings = await getSettings();
  form.elements.apiBaseUrl.value = settings.apiBaseUrl;
  form.elements.dashboardUrl.value = settings.dashboardUrl;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await saveSettings({
    apiBaseUrl: normalizeBaseUrl(form.elements.apiBaseUrl.value),
    dashboardUrl: normalizeBaseUrl(form.elements.dashboardUrl.value)
  });
  status.hidden = false;
  status.textContent = "Settings saved.";
});

void init();
