const addBtn = document.getElementById('addBtn');
const statusDiv = document.getElementById('status');

let masterPassword;
chrome.storage.local.get(['masterPassword'], (result) => {
  masterPassword = result.masterPassword;
  if (!masterPassword) {
    showStatus("Error: No master password found", "error");
    addBtn.disabled = true;
  }
});

addBtn.addEventListener('click', async () => {
  if (!masterPassword) {
    showStatus("Error: No master password", "error");
    return;
  }

  showStatus("Capturing credentials...", "");
  addBtn.disabled = true;
  
  try {
    const response = await chrome.runtime.sendMessage({
      action: "save_credentials",
      password: masterPassword
    });

    if (response.success) {
      showStatus("✓ Saved to vault!", "success");
      chrome.storage.local.remove('masterPassword');
      setTimeout(() => window.close(), 1500);
    } else {
      showStatus(response.error, "error");
    }
  } catch (err) {
    showStatus("Error: " + err.message, "error");
  } finally {
    addBtn.disabled = false;
  }
});

function showStatus(message, type) {
  statusDiv.textContent = message;
  statusDiv.className = type;
}