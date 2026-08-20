const elements = {
  enabled: document.querySelector("#enabled"),
  authority: document.querySelector("#authority"),
  username: document.querySelector("#username"),
  password: document.querySelector("#password"),
  save: document.querySelector("#save"),
  connectionStatus: document.querySelector("#connectionStatus"),
  refresh: document.querySelector("#refresh"),
  domainForm: document.querySelector("#domainForm"),
  domain: document.querySelector("#domain"),
  domainCount: document.querySelector("#domainCount"),
  domainList: document.querySelector("#domainList"),
  message: document.querySelector("#message"),
};

let settings = {};

function normalizeAuthority(value) {
  const authority = String(value || "").trim().toLowerCase();
  if (!/^[a-z0-9.-]+:\d{1,5}$/.test(authority)) {
    throw new Error("请填写有效的主机和端口");
  }
  const port = Number(authority.split(":").at(-1));
  if (port < 1 || port > 65535) {
    throw new Error("端口应为 1–65535");
  }
  return authority;
}

function basicAuthorization(username, password) {
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return `Basic ${btoa(binary)}`;
}

function showMessage(message, kind = "error") {
  elements.message.textContent = message;
  elements.message.dataset.kind = kind;
}

function clearMessage() {
  elements.message.textContent = "";
  delete elements.message.dataset.kind;
}

function renderDomains(domains) {
  elements.domainCount.textContent = String(domains.length);
  elements.domainList.replaceChildren();
  for (const domain of domains) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = domain;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "移除";
    remove.addEventListener("click", () => void removeDomain(domain));
    item.append(label, remove);
    elements.domainList.append(item);
  }
}

async function apiRequest(path, options = {}) {
  const authority = normalizeAuthority(settings.authority);
  if (!settings.username || !settings.password) {
    throw new Error("请先保存用户名和密码");
  }
  const response = await fetch(`http://${authority}${path}`, {
    ...options,
    headers: {
      Authorization: basicAuthorization(settings.username, settings.password),
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401) {
    throw new Error("用户名或密码不正确");
  }
  if (!response.ok) {
    throw new Error(payload.error || `请求失败（${response.status}）`);
  }
  return payload;
}

async function loadDomains() {
  clearMessage();
  elements.refresh.disabled = true;
  try {
    const payload = await apiRequest("/api/domains");
    renderDomains(Array.isArray(payload.domains) ? payload.domains : []);
    elements.connectionStatus.textContent = "已连接";
    elements.connectionStatus.dataset.active = "true";
  } catch (error) {
    renderDomains([]);
    elements.connectionStatus.textContent = "连接失败";
    delete elements.connectionStatus.dataset.active;
    showMessage(error.message);
  } finally {
    elements.refresh.disabled = false;
  }
}

async function addDomain(event) {
  event.preventDefault();
  const domain = elements.domain.value.trim();
  if (!domain) {
    showMessage("请输入根域名");
    return;
  }
  try {
    const payload = await apiRequest("/api/domains", {
      method: "POST",
      body: JSON.stringify({ domain }),
    });
    elements.domain.value = "";
    renderDomains(payload.domains || []);
    showMessage("已添加", "success");
  } catch (error) {
    showMessage(error.message);
  }
}

async function removeDomain(domain) {
  try {
    const payload = await apiRequest(`/api/domains/${encodeURIComponent(domain)}`, {
      method: "DELETE",
    });
    renderDomains(payload.domains || []);
    showMessage("已移除", "success");
  } catch (error) {
    showMessage(error.message);
  }
}

async function saveSettings() {
  clearMessage();
  try {
    settings = {
      enabled: elements.enabled.checked,
      authority: normalizeAuthority(elements.authority.value),
      username: elements.username.value.trim(),
      password: elements.password.value,
    };
    if (!settings.username || !settings.password) {
      throw new Error("请输入用户名和密码");
    }
    await chrome.storage.local.set(settings);
    showMessage("已保存，浏览器会自动完成代理认证", "success");
    await loadDomains();
  } catch (error) {
    showMessage(error.message);
  }
}

async function initialize() {
  settings = await chrome.storage.local.get([
    "enabled",
    "authority",
    "username",
    "password",
  ]);
  elements.enabled.checked = Boolean(settings.enabled);
  elements.authority.value = settings.authority || "43.156.119.18:31456";
  elements.username.value = settings.username || "";
  elements.password.value = settings.password || "";
  if (settings.authority && settings.username && settings.password) {
    await loadDomains();
  }
}

elements.save.addEventListener("click", () => void saveSettings());
elements.refresh.addEventListener("click", () => void loadDomains());
elements.domainForm.addEventListener("submit", (event) => void addDomain(event));
void initialize();
