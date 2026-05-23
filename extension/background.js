chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(["apiBaseUrl", "dashboardUrl"]);
  await chrome.storage.local.set({
    apiBaseUrl: current.apiBaseUrl || "http://localhost:4000",
    dashboardUrl: current.dashboardUrl || "http://localhost:5173"
  });
});
