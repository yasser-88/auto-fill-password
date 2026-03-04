chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "capture_credentials") {
    const fields = getLoginFields();
    
    if (!fields) return sendResponse({ success: false, error: "No login form found" });
    if (!fields.username) return sendResponse({ success: false, error: "No username field" });
    if (!fields.password) return sendResponse({ success: false, error: "No password field" });
    
    const username = fields.username.value?.trim();
    const password = fields.password.value;
    
    if (!username) return sendResponse({ success: false, error: "Username is empty" });
    if (!password) return sendResponse({ success: false, error: "Password is empty" });
    
    sendResponse({
      success: true,
      data: { username, password, url: window.location.href }
    });
    return true;
  }

  if (request.action === "fill_credentials") {
    const fields = getLoginFields();
    
    if (!fields) return sendResponse({ success: false, error: "No login form found" });

    if (fields.username && request.username) {
      setValue(fields.username, request.username);
    }
    if (fields.password && request.password) {
      setValue(fields.password, request.password);
    }
    
    sendResponse({ success: true });
    return true;
  }
});

function getLoginFields() {
  const passwords = Array.from(document.querySelectorAll('input[type="password"]'));
  const password = passwords.find(p => isVisible(p));
  if (!password) return null;

  const form = password.closest('form');
  let username = null;

  if (form) {
    const candidates = form.querySelectorAll('input[type="text"], input[type="email"], input:not([type])');
    username = Array.from(candidates).find(i => i !== password && isVisible(i));
  }

  return { username, password };
}

function setValue(el, value) {
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

function isVisible(el) {
  const style = window.getComputedStyle(el);
  return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
}