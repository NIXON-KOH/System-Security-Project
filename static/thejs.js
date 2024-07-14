let activeSessions = {{ active_sessions|tojson|safe }};

window.onload = function() {
    if (localStorage.getItem("tabIsOpen")) {
        if (confirm("You already have another tab open. Do you want to use this tab instead?")) {
            fetch('/invalidate_others', {method: 'POST'}).then(response => {
                localStorage.setItem("tabIsOpen", "true");
            });
        } else {
            window.location.href = "/logout";
        }
    } else {
        localStorage.setItem("tabIsOpen", "true");
    }
};

window.onbeforeunload = function() {
    localStorage.removeItem("tabIsOpen");
};

function checkStatus() {
    fetch('/status')
    .then(response => response.json())
    .then(data => {
        document.getElementById('status').innerText = data.status;
    });
}

function getAllLocalStorageData() {
            let data = {};
            for (let i = 0; i < localStorage.length; i++) {
                let key = localStorage.key(i);
                data[key] = localStorage.getItem(key);
            }
            return data;
        }

function sendDataToFlaskBackend(url) {
    let data = getAllLocalStorageData();
    
    data['activeSessionId'] = activeSessions[0]; // abit hardcoded but you get the idea
    data['uniqueTabId'] = localStorage.getItem('uniqueTabId');
    
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        console.log('Success:', result);
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function generateUniqueTabId() {
    return 'tab-' + Math.random().toString(36).substr(2, 16);
}

function setUniqueTabId() {
    tabId = generateUniqueTabId();
    localStorage.setItem('uniqueTabId', tabId);
}

window.onload = function() {
    setUniqueTabId();
    console.log('Tab ID:', localStorage.getItem('uniqueTabId'));
};

window.onbeforeunload = function() {
    localStorage.removeItem('uniqueTabId');
};

// Call this function with your Flask endpoint URL
function sendLocalStorageData() {
    if (!localStorage.getItem('uniqueTabId')) {
        localStorage.setItem('uniqueTabId', localStorage.getItem('uniqueTabId'));
    }
    if (!localStorage.getItem('token')) {
        fetch('/get_active_sessions', { method: 'GET' })
            .then(response => response.json())
            .then(data => {
                const token = data.token;
                localStorage.setItem('token', token);
                console.log('Session token set in localStorage:', token);
            })
            .catch(error => {
                console.error('Error fetching session token:', error);
            });
    }
    sendDataToFlaskBackend('/endpoint');
}