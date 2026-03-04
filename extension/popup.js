const masterPassword = document.getElementById('masterPassword');
const fillBtn = document.getElementById('fillBtn');
const statusDiv = document.getElementById('status');

chrome.storage.local.get(['masterPassword'], (result) => {
  if (result.masterPassword) {
    masterPassword.value = result.masterPassword;
  }
});

fillBtn.addEventListener('click', async () => {
  const password = masterPassword.value.trim();
  
  if (!password) {
    showStatus("Enter master password", "error");
    return;
  }

  showStatus("Filling...", "");
  fillBtn.disabled = true;
  
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    
    if (!tab.url?.startsWith('http')) {
      showStatus("Can't fill on this page", "error");
      return;
    }
    
    const domain = new URL(tab.url).hostname;
    const response = await chrome.runtime.sendMessage({
      action: "auto_fill",
      password,
      domain
    });

    if (response.success) {
      showStatus("✓ Filled!", "success");
      chrome.storage.local.remove('masterPassword');
    } else {
      if (response.error.includes("No credentials found") || response.error.includes("Not found")) {
        chrome.storage.local.set({ masterPassword: password }, () => {
          window.location.href = "fill_in.html";
        });
      } else {
        showStatus(response.error, "error");
      }
    }
  } catch (err) {
    showStatus("Failed: " + err.message, "error");
  } finally {
    fillBtn.disabled = false;
  }
});

function showStatus(message, type) {
  statusDiv.textContent = message;
  statusDiv.className = type;
}