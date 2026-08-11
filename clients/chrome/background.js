const STORAGE_KEYS = ["enabled", "authority", "username", "password"];

function normalizeAuthority(value) {
  const authority = String(value || "").trim().toLowerCase();
  if (!/^[a-z0-9.-]+:\d{1,5}$/.test(authority)) {
    return "";
  }
  const port = Number(authority.split(":").at(-1));
  return port > 0 && port <= 65535 ? authority : "";
}

function splitAuthority(authority) {
  const lastSeparator = authority.lastIndexOf(":");
  return {
    host: authority.slice(0, lastSeparator),
    port: Number(authority.slice(lastSeparator + 1)),
  };
}

async function applyProxyConfiguration() {
  const settings = await chrome.storage.local.get(STORAGE_KEYS);
  const authority = normalizeAuthority(settings.authority);
  if (!settings.enabled || !authority) {
    await chrome.proxy.settings.clear({ scope: "regular" });
    return;
  }
  await chrome.proxy.settings.set({
    scope: "regular",
    value: {
      mode: "pac_script",
      pacScript: {
        url: `http://${authority}/proxy.pac`,
        mandatory: true,
      },
    },
  });
}

chrome.runtime.onInstalled.addListener(() => {
  void applyProxyConfiguration();
});

chrome.runtime.onStartup.addListener(() => {
  void applyProxyConfiguration();
});

chrome.storage.onChanged.addListener((_changes, areaName) => {
  if (areaName === "local") {
    void applyProxyConfiguration();
  }
});

chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    if (!details.isProxy) {
      callback({});
      return;
    }
    void chrome.storage.local.get(STORAGE_KEYS).then((settings) => {
      const authority = normalizeAuthority(settings.authority);
      const expected = splitAuthority(authority);
      if (
        !settings.enabled ||
        !settings.username ||
        !settings.password ||
        details.challenger?.host?.toLowerCase() !== expected.host ||
        details.challenger?.port !== expected.port
      ) {
        callback({});
        return;
      }
      callback({
        authCredentials: {
          username: settings.username,
          password: settings.password,
        },
      });
    });
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"],
);
