const API_URL = "http://127.0.0.1:5000";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "save_credentials") {
    saveCredentials(request.password).then(sendResponse);
    return true;
  }
  
  if (request.action === "auto_fill") {
    autoFillPage(request.password, request.domain).then(sendResponse);
    return true;
  }
});

async function saveCredentials(masterPassword) {
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    const result = await chrome.tabs.sendMessage(tab.id, {
      action: "capture_credentials"
    });
    
    if (!result.success) {
      return { success: false, error: result.error };
    }
    
    const { username, password, url } = result.data;
    const domain = new URL(url).hostname;
    
    const response = await fetch(`${API_URL}/add_credentials`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        master_password: masterPassword, 
        domain,
        username,
        password
      })
    });

    const data = await response.json();
    if (!response.ok) {
      return { success: false, error: data.detail || "Failed to save" };
    }
      
    return { success: true, message: "Saved successfully!" };
  } catch (e) {
    if (e.message?.includes("Receiving end does not exist")) {
      return { success: false, error: "Please reload the page and try again" };
    }
    return { success: false, error: e.message || "Connection failed" };
  }
}

async function autoFillPage(masterPassword, domain) {
  try {
    const response = await fetch(`${API_URL}/get_credentials`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ master_password: masterPassword, domain })
    });

    const data = await response.json();
    if (!response.ok) {
      return { success: false, error: data.detail || "Not found" };
    }
      
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    await chrome.tabs.sendMessage(tab.id, {
      action: "fill_credentials",
      username: data.username,
      password: data.password
    });
    
    return { success: true };
  } catch (e) {
    if (e.message?.includes("Receiving end does not exist")) {
      return { success: false, error: "Please reload the page and try again" };
    }
    return { success: false, error: "Connection failed" };
  }
}