/**
 * FindMyInfo — Core Application Script
 * Handcrafted vanilla ES6 implementation for diagnostics, APIs, local database, and UX.
 */

document.addEventListener('DOMContentLoaded', () => {
  
  // ----------------------------------------------------
  // STATE MANAGEMENT
  // ----------------------------------------------------
  const state = {
    activeTab: 'dashboard',
    systemInfo: {},
    networkInfo: {},
    weatherInfo: {},
    vaultItems: [],
    spotlightOpen: false,
    selectedSpotlightIndex: -1,
    spotlightResults: [],
    facts: [
      "Modern web browsers can access your physical battery status via the Battery Status API.",
      "The Geolocation API can request precise GPS coordinates, but we use IP-based routing here to avoid annoying browser prompts.",
      "Vibrant dark interfaces reduce screen power consumption on OLED displays by up to 60%.",
      "Pressing Ctrl+K triggers the Spotlight search from anywhere on the page, like in MacOS or VS Code.",
      "The data saved in your Secure Vault never leaves your browser; it is stored inside the HTML5 LocalStorage sandbox.",
      "Your screen refresh rate and pixel depth can be analyzed to profile screen capabilities for graphics processing.",
      "Logical CPU cores represent the number of parallel processing threads your device can run simultaneously."
    ],
    currentFactIndex: 0,
    
    // Auth Session State
    sessionKey: null,
    username: null
  };

  // ----------------------------------------------------
  // DOM ELEMENT REFERENCES
  // ----------------------------------------------------
  const elements = {
    // Auth Overlay Screens
    authScreen: document.getElementById('auth-screen'),
    authSubtitle: document.getElementById('auth-subtitle'),
    authLoginForm: document.getElementById('auth-login-form'),
    loginPassword: document.getElementById('login-password'),
    authRegisterForm: document.getElementById('auth-register-form'),
    registerUsername: document.getElementById('register-username'),
    registerPassword: document.getElementById('register-password'),
    registerConfirm: document.getElementById('register-confirm'),
    
    // Sidebar User
    sidebarUserPanel: document.getElementById('sidebar-user-panel'),
    userDisplayName: document.getElementById('user-display-name'),
    logoutTrigger: document.getElementById('logout-trigger'),

    // Navigation
    navItems: document.querySelectorAll('.nav-item'),
    tabPanes: document.querySelectorAll('.tab-pane'),
    
    // Header & Status
    liveTime: document.getElementById('live-time'),
    statusPulse: document.getElementById('status-pulse'),
    connectionStatusText: document.getElementById('connection-status-text'),
    spotlightTrigger: document.getElementById('spotlight-trigger'),
    
    // Spotlight Search
    spotlightOverlay: document.getElementById('spotlight-overlay'),
    spotlightInput: document.getElementById('spotlight-input'),
    spotlightResults: document.getElementById('spotlight-results'),
    
    // Dashboard Stats
    pillIp: document.getElementById('pill-ip'),
    pillOs: document.getElementById('pill-os'),
    dashIp: document.getElementById('dash-ip'),
    dashIsp: document.getElementById('dash-isp'),
    dashLocation: document.getElementById('dash-location'),
    dashBrowser: document.getElementById('dash-browser'),
    dashCpu: document.getElementById('dash-cpu'),
    dashBattery: document.getElementById('dash-battery'),
    dashTemp: document.getElementById('dash-temp'),
    dashWeatherDesc: document.getElementById('dash-weather-desc'),
    dashWind: document.getElementById('dash-wind'),
    dashTimezone: document.getElementById('dash-timezone'),
    dashVaultCount: document.getElementById('dash-vault-count'),
    systemFact: document.getElementById('system-fact'),
    nextFactBtn: document.getElementById('next-fact-btn'),
    
    // Network Details
    netIp: document.getElementById('net-ip'),
    netIsp: document.getElementById('net-isp'),
    netOrg: document.getElementById('net-org'),
    netCountry: document.getElementById('net-country'),
    netCity: document.getElementById('net-city'),
    netCoords: document.getElementById('net-coords'),
    netSpeed: document.getElementById('net-speed'),
    runSpeedTest: document.getElementById('run-speed-test'),
    mapContainer: document.getElementById('leaflet-map'),
    
    // System Details
    sysCpuCores: document.getElementById('sys-cpu-cores'),
    sysRam: document.getElementById('sys-ram'),
    sysPlatform: document.getElementById('sys-platform'),
    sysLang: document.getElementById('sys-lang'),
    sysResolution: document.getElementById('sys-resolution'),
    sysAvailScreen: document.getElementById('sys-avail-screen'),
    sysColorDepth: document.getElementById('sys-color-depth'),
    sysPixelRatio: document.getElementById('sys-pixel-ratio'),
    batteryIndicator: document.getElementById('battery-indicator'),
    batteryChargingBolt: document.getElementById('battery-charging-bolt'),
    sysBatteryPct: document.getElementById('sys-battery-pct'),
    sysBatteryStatus: document.getElementById('sys-battery-status'),
    sysUserAgent: document.getElementById('sys-user-agent'),
    
    // Vault Elements
    vaultForm: document.getElementById('vault-form'),
    vaultId: document.getElementById('vault-id'),
    vaultTitle: document.getElementById('vault-title'),
    vaultCategory: document.getElementById('vault-category'),
    vaultContent: document.getElementById('vault-content'),
    vaultTags: document.getElementById('vault-tags'),
    vaultSaveBtn: document.getElementById('vault-save-btn'),
    vaultCancelBtn: document.getElementById('vault-cancel-btn'),
    vaultFormTitle: document.getElementById('vault-form-title'),
    vaultListSearch: document.getElementById('vault-list-search'),
    vaultItemsList: document.getElementById('vault-items-list')
  };

  // Map references
  let leafletMap = null;
  let mapMarker = null;

  // ----------------------------------------------------
  // AUTHENTICATION LOGIC (LOCAL MASTER PASSWORD)
  // ----------------------------------------------------
  
  // Standard SHA-256 Hashing helper using Web Crypto API
  async function hashPassword(password) {
    const msgUint8 = new TextEncoder().encode(password + '_findmyinfo_salt_key'); // salting credentials
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Lightweight symmetric encryption using XOR + Base64
  function encryptText(text, key) {
    if (!text) return '';
    const textEncoder = new TextEncoder();
    const encoded = textEncoder.encode(text);
    const encrypted = new Uint8Array(encoded.length);
    for (let i = 0; i < encoded.length; i++) {
      encrypted[i] = encoded[i] ^ key.charCodeAt(i % key.length);
    }
    // Convert Uint8Array to binary string before encoding to base64
    let binString = "";
    for (let i = 0; i < encrypted.length; i++) {
      binString += String.fromCharCode(encrypted[i]);
    }
    return btoa(binString);
  }

  // Lightweight symmetric decryption using XOR + Base64
  function decryptText(encodedBase64, key) {
    if (!encodedBase64) return '';
    try {
      const binary = atob(encodedBase64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i) ^ key.charCodeAt(i % key.length);
      }
      const textDecoder = new TextDecoder();
      return textDecoder.decode(bytes);
    } catch (e) {
      console.error('Decryption failed', e);
      return '[Decryption Failed - Invalid Session Key]';
    }
  }

  async function checkAuth() {
    const storedHash = localStorage.getItem('findmyinfo_password_hash');
    const storedUsername = localStorage.getItem('findmyinfo_username');

    if (!storedHash || !storedUsername) {
      // First boot: show registration
      elements.authLoginForm.classList.add('hidden');
      elements.authRegisterForm.classList.remove('hidden');
      elements.authSubtitle.textContent = 'Setup your Master Profile username and password to secure your local environment.';
    } else {
      // Show login
      elements.authRegisterForm.classList.add('hidden');
      elements.authLoginForm.classList.remove('hidden');
      elements.authSubtitle.textContent = `Welcome back. Enter password for account "${storedUsername}" to unlock dashboard.`;
    }
    
    // Focus appropriate password input
    setTimeout(() => {
      if (!storedHash) {
        elements.registerUsername.focus();
      } else {
        elements.loginPassword.focus();
      }
    }, 150);
  }

  function setupAuthEvents() {
    // 1. Handle Registration
    elements.authRegisterForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const username = elements.registerUsername.value.trim();
      const pwd = elements.registerPassword.value;
      const confirmPwd = elements.registerConfirm.value;

      if (pwd !== confirmPwd) {
        triggerAuthShake(elements.authRegisterForm);
        alert("Passwords do not match!");
        return;
      }

      if (pwd.length < 4) {
        triggerAuthShake(elements.authRegisterForm);
        alert("Password must be at least 4 characters.");
        return;
      }

      // Hash credentials and store
      const hash = await hashPassword(pwd);
      localStorage.setItem('findmyinfo_username', username);
      localStorage.setItem('findmyinfo_password_hash', hash);

      // Log the user in
      state.sessionKey = pwd;
      state.username = username;
      unlockDashboard();
    });

    // 2. Handle Login
    elements.authLoginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const pwd = elements.loginPassword.value;
      const hash = await hashPassword(pwd);
      const storedHash = localStorage.getItem('findmyinfo_password_hash');
      const storedUsername = localStorage.getItem('findmyinfo_username');

      if (hash === storedHash) {
        state.sessionKey = pwd;
        state.username = storedUsername;
        unlockDashboard();
      } else {
        triggerAuthShake(elements.authLoginForm);
        elements.loginPassword.value = '';
        elements.loginPassword.focus();
      }
    });

    // 3. Handle Logout
    elements.logoutTrigger.addEventListener('click', () => {
      performLogout();
    });
  }

  function triggerAuthShake(formElement) {
    formElement.classList.add('auth-shake');
    setTimeout(() => {
      formElement.classList.remove('auth-shake');
    }, 400);
  }

  function unlockDashboard() {
    // Fade out overlay screen
    elements.authScreen.classList.add('fade-out');
    
    // Configure user profile sidebar panel
    elements.userDisplayName.textContent = state.username;
    elements.sidebarUserPanel.classList.remove('hidden');

    // Run core modules initialization
    initializeAfterAuth();
  }

  function performLogout() {
    // Clear session details
    state.sessionKey = null;
    state.username = null;
    state.vaultItems = [];
    
    // Clear input fields
    elements.loginPassword.value = '';
    elements.registerUsername.value = '';
    elements.registerPassword.value = '';
    elements.registerConfirm.value = '';

    // Hide profile and show auth gate
    elements.sidebarUserPanel.classList.add('hidden');
    elements.authScreen.classList.remove('fade-out');
    
    // Re-verify login mode
    checkAuth();
  }

  // ----------------------------------------------------
  // CORE DASHBOARD INIT (POST-AUTHENTICATION)
  // ----------------------------------------------------
  function initializeAfterAuth() {
    detectDeviceSpecs();
    fetchNetworkDetails();
    initSpeedTest();
    initVault();
    initSpotlight();
    initFactRotator();
  }

  // ----------------------------------------------------
  // 1. ROUTING & TABS CONTROLLER
  // ----------------------------------------------------
  function initTabs() {
    elements.navItems.forEach(item => {
      item.addEventListener('click', () => {
        const tabId = item.getAttribute('data-tab');
        switchTab(tabId);
      });
    });
  }

  function switchTab(tabId) {
    state.activeTab = tabId;
    
    // Update active class on nav buttons
    elements.navItems.forEach(btn => {
      if (btn.getAttribute('data-tab') === tabId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    // Toggle visible panels
    elements.tabPanes.forEach(pane => {
      if (pane.id === `tab-${tabId}`) {
        pane.classList.add('active');
      } else {
        pane.classList.remove('active');
      }
    });

    // Special handlers when changing views
    if (tabId === 'network') {
      // Leaflet requires invalidating size if rendered in hidden container initially
      setTimeout(() => {
        if (leafletMap) {
          leafletMap.invalidateSize();
        }
      }, 100);
    }
  }

  // ----------------------------------------------------
  // 2. REAL-TIME CLOCK & STATUS MONITOR
  // ----------------------------------------------------
  function startClock() {
    setInterval(() => {
      const now = new Date();
      elements.liveTime.textContent = now.toLocaleTimeString();
    }, 1000);
  }

  function monitorConnection() {
    const updateStatus = () => {
      if (navigator.onLine) {
        elements.statusPulse.className = 'pulse-indicator online';
        elements.connectionStatusText.textContent = 'System Online';
      } else {
        elements.statusPulse.className = 'pulse-indicator offline';
        elements.connectionStatusText.textContent = 'System Offline';
      }
    };

    window.addEventListener('online', updateStatus);
    window.addEventListener('offline', updateStatus);
    updateStatus(); // Initial call
  }

  // ----------------------------------------------------
  // 3. HARDWARE & DEVICE DIAGNOSTICS
  // ----------------------------------------------------
  function detectDeviceSpecs() {
    const specs = {};
    
    // Screen parameters
    specs.resolution = `${window.screen.width} x ${window.screen.height}`;
    specs.availResolution = `${window.screen.availWidth} x ${window.screen.availHeight}`;
    specs.colorDepth = window.screen.colorDepth;
    specs.pixelRatio = window.devicePixelRatio || 1;
    
    // Hardware cores & RAM
    specs.cpuCores = navigator.hardwareConcurrency || 'Unavailable';
    specs.ram = navigator.deviceMemory ? `${navigator.deviceMemory} GB` : 'Unavailable';
    specs.language = navigator.language || navigator.userLanguage || 'Unknown';
    
    // Detect OS from agent
    const userAgent = navigator.userAgent;
    let platform = "Unknown OS";
    if (userAgent.indexOf("Win") !== -1) platform = "Windows";
    if (userAgent.indexOf("Mac") !== -1) platform = "macOS";
    if (userAgent.indexOf("X11") !== -1) platform = "UNIX";
    if (userAgent.indexOf("Linux") !== -1) platform = "Linux";
    if (/Android/.test(userAgent)) platform = "Android";
    if (/iPhone|iPad|iPod/.test(userAgent)) platform = "iOS";
    
    specs.os = platform;
    specs.userAgent = userAgent;

    // Browser detect
    let browser = "Unknown Browser";
    if (userAgent.indexOf("Chrome") !== -1 && userAgent.indexOf("Safari") !== -1 && userAgent.indexOf("Edg") === -1) {
      browser = "Google Chrome";
    } else if (userAgent.indexOf("Safari") !== -1 && userAgent.indexOf("Chrome") === -1) {
      browser = "Apple Safari";
    } else if (userAgent.indexOf("Firefox") !== -1) {
      browser = "Mozilla Firefox";
    } else if (userAgent.indexOf("Edg") !== -1) {
      browser = "Microsoft Edge";
    } else if (userAgent.indexOf("Trident") !== -1) {
      browser = "Internet Explorer";
    }
    specs.browser = browser;

    state.systemInfo = specs;
    renderSystemSpecs();
  }

  function renderSystemSpecs() {
    const { systemInfo } = state;
    
    // Top headers/pills
    elements.pillOs.textContent = `OS: ${systemInfo.os}`;
    
    // Dashboard fields
    elements.dashBrowser.textContent = systemInfo.browser;
    elements.dashCpu.textContent = `${systemInfo.cpuCores} Threads`;
    
    // System diagnostics panel
    elements.sysCpuCores.textContent = systemInfo.cpuCores;
    elements.sysRam.textContent = systemInfo.ram;
    elements.sysPlatform.textContent = systemInfo.os;
    elements.sysLang.textContent = systemInfo.language.toUpperCase();
    elements.sysResolution.textContent = systemInfo.resolution;
    elements.sysAvailScreen.textContent = systemInfo.availResolution;
    elements.sysColorDepth.textContent = `${systemInfo.colorDepth}-bit`;
    elements.sysPixelRatio.textContent = systemInfo.pixelRatio;
    elements.sysUserAgent.textContent = systemInfo.userAgent;
    
    // Handle battery info
    detectBattery();
  }

  function detectBattery() {
    if ('getBattery' in navigator) {
      navigator.getBattery().then(battery => {
        const updateBatteryUI = () => {
          const level = Math.round(battery.level * 100);
          const isCharging = battery.charging;
          
          // Width & colors
          elements.batteryIndicator.style.width = `${level}%`;
          if (level <= 20) {
            elements.batteryIndicator.style.backgroundColor = 'var(--accent-pink)';
          } else if (level <= 50) {
            elements.batteryIndicator.style.backgroundColor = '#f59e0b'; // Amber
          } else {
            elements.batteryIndicator.style.backgroundColor = 'var(--accent-cyan)';
          }
          
          // Charging icon
          if (isCharging) {
            elements.batteryChargingBolt.classList.add('charging');
            elements.sysBatteryStatus.textContent = "Charging";
            elements.dashBattery.textContent = `${level}% (Charging)`;
          } else {
            elements.batteryChargingBolt.classList.remove('charging');
            elements.sysBatteryStatus.textContent = "Discharging";
            elements.dashBattery.textContent = `${level}%`;
          }
          
          elements.sysBatteryPct.textContent = `${level}%`;
        };

        updateBatteryUI();

        // Listen for changes
        battery.addEventListener('levelchange', updateBatteryUI);
        battery.addEventListener('chargingchange', updateBatteryUI);
      });
    } else {
      elements.sysBatteryPct.textContent = 'Unsupported';
      elements.sysBatteryStatus.textContent = 'API Unavailable in this browser';
      elements.dashBattery.textContent = 'Unsupported';
      elements.batteryIndicator.style.width = '100%';
      elements.batteryIndicator.style.backgroundColor = 'var(--text-dim)';
    }
  }

  // ----------------------------------------------------
  // 4. NETWORK & LOCATION/WEATHER API INTEGRATION
  // ----------------------------------------------------
  async function fetchNetworkDetails() {
    try {
      // Use ipapi.co (HTTPS-friendly free IP details endpoint)
      const response = await fetch('https://ipapi.co/json/');
      if (!response.ok) throw new Error('Network response details failed.');
      
      const data = await response.json();
      
      state.networkInfo = {
        ip: data.ip || 'Unavailable',
        isp: data.org || data.asn || 'Unknown Provider',
        org: data.org || 'Unknown Org',
        country: data.country_name || 'Unknown Country',
        city: data.city || 'Unknown City',
        region: data.region || '',
        zip: data.postal || '',
        latitude: parseFloat(data.latitude),
        longitude: parseFloat(data.longitude),
        timezone: data.timezone || 'UTC'
      };
      
      renderNetworkInfo();
      
      // Once we have coordinates, trigger weather and maps loading
      if (!isNaN(state.networkInfo.latitude) && !isNaN(state.networkInfo.longitude)) {
        fetchLocalWeather(state.networkInfo.latitude, state.networkInfo.longitude);
        initializeMap(state.networkInfo.latitude, state.networkInfo.longitude, state.networkInfo.city);
      }
      
    } catch (error) {
      console.error("IP Geolocation Fetch Failed: ", error);
      // Fallback display
      elements.pillIp.textContent = "IP: Offline/Blocked";
      elements.dashIp.textContent = "Unavailable";
      elements.dashIsp.textContent = "Check adblocker or connection";
      elements.dashLocation.textContent = "Unknown location";
      elements.netIp.textContent = "Failed to load IP";
      elements.netIsp.textContent = "Check network status";
      elements.netOrg.textContent = "Unavailable";
      elements.netCountry.textContent = "Unknown";
      elements.netCity.textContent = "Unknown";
      elements.netCoords.textContent = "Unknown coordinates";
      elements.dashTimezone.textContent = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    }
  }

  function renderNetworkInfo() {
    const { networkInfo } = state;
    
    // Pills
    elements.pillIp.textContent = `IP: ${networkInfo.ip}`;
    
    // Dashboard Summaries
    elements.dashIp.textContent = networkInfo.ip;
    elements.dashIsp.textContent = networkInfo.isp;
    elements.dashLocation.textContent = `${networkInfo.city}, ${networkInfo.country}`;
    elements.dashTimezone.textContent = networkInfo.timezone;
    
    // Network tab detailed list
    elements.netIp.textContent = networkInfo.ip;
    elements.netIsp.textContent = networkInfo.isp;
    elements.netOrg.textContent = networkInfo.org;
    elements.netCountry.textContent = networkInfo.country;
    elements.netCity.textContent = `${networkInfo.city} ${networkInfo.zip ? '(' + networkInfo.zip + ')' : ''}`;
    elements.netCoords.textContent = `${networkInfo.latitude.toFixed(4)}, ${networkInfo.longitude.toFixed(4)}`;
    
    // Setup copying of IP address
    setupIpCopying();
  }

  function setupIpCopying() {
    const copyIP = async (element) => {
      const ip = element.textContent;
      if (ip && ip !== 'Loading...' && ip !== 'Unavailable') {
        try {
          await navigator.clipboard.writeText(ip);
          const originalText = element.textContent;
          element.textContent = 'Copied!';
          element.style.color = 'var(--accent-cyan)';
          setTimeout(() => {
            element.textContent = originalText;
            element.style.color = '';
          }, 1500);
        } catch (err) {
          console.error('Failed to copy text: ', err);
        }
      }
    };

    // Remove duplicates if listening multiple times
    const newNetIp = elements.netIp.cloneNode(true);
    elements.netIp.parentNode.replaceChild(newNetIp, elements.netIp);
    elements.netIp = newNetIp;

    elements.netIp.addEventListener('click', () => copyIP(elements.netIp));
  }

  // ----------------------------------------------------
  // 5. WEATHER INTEGRATION (Open-Meteo)
  // ----------------------------------------------------
  async function fetchLocalWeather(lat, lon) {
    try {
      const weatherUrl = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current=temperature_2m,relative_humidity_2m,apparent_temperature,is_day,precipitation,rain,showers,snowfall,weather_code,wind_speed_10m&timezone=auto`;
      const response = await fetch(weatherUrl);
      if (!response.ok) throw new Error('Weather API retrieval failed.');
      
      const data = await response.json();
      const current = data.current;
      
      state.weatherInfo = {
        temp: current.temperature_2m,
        wind: current.wind_speed_10m,
        code: current.weather_code,
        apparent: current.apparent_temperature
      };
      
      renderWeather();
    } catch (e) {
      console.error("Weather fetch failed: ", e);
      elements.dashTemp.textContent = '--';
      elements.dashWeatherDesc.textContent = 'Weather information temporarily unavailable';
    }
  }

  function getWeatherCodeDescription(code) {
    const mapping = {
      0: "Clear sky",
      1: "Mainly clear",
      2: "Partly cloudy",
      3: "Overcast",
      45: "Foggy",
      48: "Depositing rime fog",
      51: "Light drizzle",
      53: "Moderate drizzle",
      55: "Dense drizzle",
      61: "Slight rain",
      63: "Moderate rain",
      65: "Heavy rain",
      71: "Slight snow fall",
      73: "Moderate snow fall",
      75: "Heavy snow fall",
      77: "Snow grains",
      80: "Slight rain showers",
      81: "Moderate rain showers",
      82: "Violent rain showers",
      85: "Slight snow showers",
      86: "Heavy snow showers",
      95: "Thunderstorm",
      96: "Thunderstorm with slight hail",
      99: "Thunderstorm with heavy hail"
    };
    return mapping[code] || "Conditions Normal";
  }

  function renderWeather() {
    const { weatherInfo } = state;
    elements.dashTemp.textContent = `${Math.round(weatherInfo.temp)}°C`;
    elements.dashWind.textContent = `${weatherInfo.wind} km/h`;
    elements.dashWeatherDesc.textContent = `${getWeatherCodeDescription(weatherInfo.code)}, feels like ${Math.round(weatherInfo.apparent)}°C.`;
  }

  // ----------------------------------------------------
  // 6. LEAFLET MAP DRAWING (Dark Mode Theme)
  // ----------------------------------------------------
  function initializeMap(lat, lon, cityName) {
    // If map already exists, just update position
    if (leafletMap) {
      leafletMap.setView([lat, lon], 12);
      if (mapMarker) {
        mapMarker.setLatLng([lat, lon]);
        mapMarker.setPopupContent(`<b>Approx. Location</b><br>${cityName}`);
      }
      return;
    }

    // Initialize map
    leafletMap = L.map('leaflet-map', {
      zoomControl: true,
      attributionControl: false
    }).setView([lat, lon], 11);

    // Dark tiles from CartoDB (completely free, premium appearance)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 19
    }).addTo(leafletMap);

    // Circular glowing marker representing approximation
    mapMarker = L.circle([lat, lon], {
      color: 'var(--accent-indigo)',
      fillColor: 'var(--accent-indigo)',
      fillOpacity: 0.2,
      radius: 1200 // 1.2 KM area
    }).addTo(leafletMap);
    
    mapMarker.bindPopup(`<b>Approx. Location</b><br>${cityName}`).openPopup();
  }

  // ----------------------------------------------------
  // 7. SPEED DIAGNOSTICS TESTER
  // ----------------------------------------------------
  function initSpeedTest() {
    const triggerSpeedTest = async () => {
      elements.netSpeed.textContent = 'Running test...';
      elements.runSpeedTest.disabled = true;
      
      const testAssetUrl = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js?cachebreak=' + Math.random();
      
      let totalDuration = 0;
      let failedAttempts = 0;
      const iterations = 3;

      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();
        try {
          const res = await fetch(testAssetUrl);
          if (!res.ok) throw new Error('Fetch failed');
          await res.blob();
          const endTime = performance.now();
          totalDuration += (endTime - startTime);
        } catch (e) {
          failedAttempts++;
        }
      }

      if (failedAttempts === iterations) {
        elements.netSpeed.textContent = 'Speed test failed. Check connection.';
        elements.runSpeedTest.disabled = false;
        return;
      }

      const averageDurationMs = totalDuration / (iterations - failedAttempts);
      const sizeBytes = 150000;
      
      const speedBps = sizeBytes / (averageDurationMs / 1000);
      const speedMbps = (speedBps * 8) / (1024 * 1024);
      
      elements.netSpeed.textContent = `${speedMbps.toFixed(2)} Mbps`;
      elements.runSpeedTest.disabled = false;
    };

    // Re-bind to prevent double-firing
    const newBtn = elements.runSpeedTest.cloneNode(true);
    elements.runSpeedTest.parentNode.replaceChild(newBtn, elements.runSpeedTest);
    elements.runSpeedTest = newBtn;
    
    elements.runSpeedTest.addEventListener('click', triggerSpeedTest);
  }

  // ----------------------------------------------------
  // 8. SECURE STORAGE PERSONAL VAULT MANAGER
  // ----------------------------------------------------
  function initVault() {
    loadVaultItems();

    // Reset bindings
    const newForm = elements.vaultForm.cloneNode(true);
    elements.vaultForm.parentNode.replaceChild(newForm, elements.vaultForm);
    elements.vaultForm = newForm;

    // Grab new references inside new form
    elements.vaultId = document.getElementById('vault-id');
    elements.vaultTitle = document.getElementById('vault-title');
    elements.vaultCategory = document.getElementById('vault-category');
    elements.vaultContent = document.getElementById('vault-content');
    elements.vaultTags = document.getElementById('vault-tags');
    elements.vaultSaveBtn = document.getElementById('vault-save-btn');
    elements.vaultCancelBtn = document.getElementById('vault-cancel-btn');
    elements.vaultFormTitle = document.getElementById('vault-form-title');

    elements.vaultForm.addEventListener('submit', (e) => {
      e.preventDefault();
      
      const id = elements.vaultId.value;
      const title = elements.vaultTitle.value.trim();
      const category = elements.vaultCategory.value;
      const content = elements.vaultContent.value.trim();
      const tags = elements.vaultTags.value
        .split(',')
        .map(t => t.trim())
        .filter(t => t.length > 0);
        
      if (id) {
        // Edit existing
        const index = state.vaultItems.findIndex(item => item.id === id);
        if (index !== -1) {
          state.vaultItems[index] = { ...state.vaultItems[index], title, category, content, tags, updated: Date.now() };
        }
      } else {
        // Create new
        const newItem = {
          id: 'vault_' + Date.now() + '_' + Math.floor(Math.random()*1000),
          title,
          category,
          content,
          tags,
          created: Date.now()
        };
        state.vaultItems.push(newItem);
      }
      
      saveVaultItems();
      resetVaultForm();
      renderVaultItems();
      updateDashboardVaultCount();
    });

    elements.vaultCancelBtn.addEventListener('click', resetVaultForm);

    // Filter search binding
    const newSearch = elements.vaultListSearch.cloneNode(true);
    elements.vaultListSearch.parentNode.replaceChild(newSearch, elements.vaultListSearch);
    elements.vaultListSearch = newSearch;
    elements.vaultListSearch.addEventListener('input', () => {
      renderVaultItems();
    });
  }

  function loadVaultItems() {
    try {
      const stored = localStorage.getItem('findmyinfo_vault');
      const encryptedItems = stored ? JSON.parse(stored) : [];
      
      // Decrypt all items in-memory using our master password key
      state.vaultItems = encryptedItems.map(item => {
        return {
          ...item,
          content: decryptText(item.content, state.sessionKey)
        };
      });
      
      updateDashboardVaultCount();
      renderVaultItems();
    } catch (e) {
      console.error("Local storage retrieval failed: ", e);
      state.vaultItems = [];
    }
  }

  function saveVaultItems() {
    try {
      // Encrypt all items in LocalStorage using our master password key
      const encryptedItems = state.vaultItems.map(item => {
        return {
          ...item,
          content: encryptText(item.content, state.sessionKey)
        };
      });
      localStorage.setItem('findmyinfo_vault', JSON.stringify(encryptedItems));
    } catch (e) {
      alert("Storage write failure. LocalStorage limits exceeded.");
    }
  }

  function updateDashboardVaultCount() {
    elements.dashVaultCount.textContent = state.vaultItems.length;
  }

  function resetVaultForm() {
    elements.vaultId.value = '';
    elements.vaultForm.reset();
    elements.vaultFormTitle.textContent = 'Save New Record';
    elements.vaultSaveBtn.textContent = 'Save Info';
    elements.vaultCancelBtn.classList.add('hidden');
  }

  function renderVaultItems() {
    const filterText = elements.vaultListSearch.value.toLowerCase().trim();
    elements.vaultItemsList.innerHTML = '';
    
    const filtered = state.vaultItems.filter(item => {
      return (
        item.title.toLowerCase().includes(filterText) ||
        item.content.toLowerCase().includes(filterText) ||
        item.category.toLowerCase().includes(filterText) ||
        item.tags.some(tag => tag.toLowerCase().includes(filterText))
      );
    });

    if (filtered.length === 0) {
      elements.vaultItemsList.innerHTML = `
        <div class="empty-state">
          <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
          </svg>
          <p>${state.vaultItems.length === 0 ? 'Your local vault is empty. Save something above to get started!' : 'No records match your filter criteria.'}</p>
        </div>
      `;
      return;
    }

    // Sort: newest first
    filtered.sort((a,b) => b.created - a.created);

    filtered.forEach(item => {
      const itemEl = document.createElement('div');
      itemEl.className = 'vault-item';
      
      const isCredentials = item.category === 'Credentials';
      const maskedContent = isCredentials ? '•••••••• (Secure Credential — Click Edit to reveal/view)' : escapeHTML(item.content);
      const catClass = item.category.toLowerCase().replace(' ', '-');

      itemEl.innerHTML = `
        <div class="vault-item-header">
          <span class="vault-item-title">${escapeHTML(item.title)}</span>
          <div class="vault-item-meta">
            <span class="category-badge ${catClass}">${escapeHTML(item.category)}</span>
          </div>
        </div>
        <div class="vault-item-body code-font">${maskedContent}</div>
        ${item.tags.length > 0 ? `
          <div class="vault-item-tags">
            ${item.tags.map(tag => `<span class="tag-pill">#${escapeHTML(tag)}</span>`).join('')}
          </div>
        ` : ''}
        <div class="vault-item-actions">
          <button class="action-btn edit" data-id="${item.id}">Edit</button>
          <button class="action-btn delete" data-id="${item.id}">Delete</button>
        </div>
      `;
      
      // Wire up action buttons
      itemEl.querySelector('.edit').addEventListener('click', () => editVaultItem(item.id));
      itemEl.querySelector('.delete').addEventListener('click', () => deleteVaultItem(item.id));

      elements.vaultItemsList.appendChild(itemEl);
    });
  }

  function editVaultItem(id) {
    const item = state.vaultItems.find(i => i.id === id);
    if (!item) return;

    elements.vaultId.value = item.id;
    elements.vaultTitle.value = item.title;
    elements.vaultCategory.value = item.category;
    elements.vaultContent.value = item.content;
    elements.vaultTags.value = item.tags.join(', ');

    elements.vaultFormTitle.textContent = 'Edit Saved Record';
    elements.vaultSaveBtn.textContent = 'Update Info';
    elements.vaultCancelBtn.classList.remove('hidden');

    elements.vaultTitle.scrollIntoView({ behavior: 'smooth' });
    elements.vaultTitle.focus();
  }

  function deleteVaultItem(id) {
    if (confirm("Are you sure you want to delete this info record? This action is permanent.")) {
      state.vaultItems = state.vaultItems.filter(item => item.id !== id);
      saveVaultItems();
      renderVaultItems();
      updateDashboardVaultCount();
      if (elements.vaultId.value === id) {
        resetVaultForm();
      }
    }
  }

  function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
      tag => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
      }[tag] || tag)
    );
  }

  // ----------------------------------------------------
  // 9. UNIVERSAL SPOTLIGHT SEARCH ENGINE (Cmd/Ctrl + K)
  // ----------------------------------------------------
  function initSpotlight() {
    // Open when clicking header trigger button
    elements.spotlightTrigger.addEventListener('click', openSpotlight);
    
    // Close when overlay is clicked directly
    elements.spotlightOverlay.addEventListener('click', (e) => {
      if (e.target === elements.spotlightOverlay) {
        closeSpotlight();
      }
    });

    // Keyboard bindings (remove global listeners if re-binding to prevent multiples)
    const handleKeydowns = (e) => {
      // Toggle Spotlight
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        // If not logged in, ignore shortcut
        if (!state.sessionKey) return;
        if (state.spotlightOpen) {
          closeSpotlight();
        } else {
          openSpotlight();
        }
      }

      // Escape key to close
      if (e.key === 'Escape' && state.spotlightOpen) {
        closeSpotlight();
      }

      // Spotlight navigation keys
      if (state.spotlightOpen) {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          navigateSpotlight(1);
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          navigateSpotlight(-1);
        } else if (e.key === 'Enter') {
          e.preventDefault();
          selectSpotlightItem();
        }
      }
    };

    window.removeEventListener('keydown', handleKeydowns);
    window.addEventListener('keydown', handleKeydowns);

    elements.spotlightInput.addEventListener('input', () => {
      executeSpotlightSearch();
    });
  }

  function openSpotlight() {
    state.spotlightOpen = true;
    state.selectedSpotlightIndex = -1;
    elements.spotlightInput.value = '';
    elements.spotlightOverlay.classList.add('open');
    elements.spotlightResults.innerHTML = `
      <div class="spotlight-instruction">
        <p>Type to search diagnostic properties (e.g., <code>IP</code>, <code>Cores</code>, <code>Screen</code>) or saved vault database notes.</p>
      </div>
    `;
    setTimeout(() => {
      elements.spotlightInput.focus();
    }, 100);
  }

  function closeSpotlight() {
    state.spotlightOpen = false;
    elements.spotlightOverlay.classList.remove('open');
  }

  function executeSpotlightSearch() {
    const query = elements.spotlightInput.value.toLowerCase().trim();
    elements.spotlightResults.innerHTML = '';
    state.selectedSpotlightIndex = -1;
    
    if (query === '') {
      elements.spotlightResults.innerHTML = `
        <div class="spotlight-instruction">
          <p>Type to search diagnostic properties (e.g., <code>IP</code>, <code>Cores</code>, <code>Screen</code>) or saved vault database notes.</p>
        </div>
      `;
      state.spotlightResults = [];
      return;
    }

    const results = [];

    // 1. Search Static Diagnostics
    const diagSource = [
      { key: 'ip', val: state.networkInfo.ip, title: 'Network IP Address', sub: `Public Address: ${state.networkInfo.ip}`, tab: 'network' },
      { key: 'isp', val: state.networkInfo.isp, title: 'Network Provider (ISP)', sub: `Provider: ${state.networkInfo.isp}`, tab: 'network' },
      { key: 'cores', val: state.systemInfo.cpuCores, title: 'CPU Cores / Threads', sub: `Hardware Thread Count: ${state.systemInfo.cpuCores}`, tab: 'system' },
      { key: 'cores', val: 'cpu', title: 'CPU Cores / Threads', sub: `Hardware Thread Count: ${state.systemInfo.cpuCores}`, tab: 'system' },
      { key: 'ram', val: state.systemInfo.ram, title: 'System Memory (RAM)', sub: `Device RAM: ${state.systemInfo.ram}`, tab: 'system' },
      { key: 'screen', val: state.systemInfo.resolution, title: 'Display Screen Resolution', sub: `Res: ${state.systemInfo.resolution}`, tab: 'system' },
      { key: 'screen', val: 'resolution', title: 'Display Screen Resolution', sub: `Res: ${state.systemInfo.resolution}`, tab: 'system' },
      { key: 'os', val: state.systemInfo.os, title: 'Operating System', sub: `OS: ${state.systemInfo.os}`, tab: 'system' },
      { key: 'browser', val: state.systemInfo.browser, title: 'Browser Client', sub: `Browser: ${state.systemInfo.browser}`, tab: 'system' }
    ];

    diagSource.forEach(item => {
      if (
        item.title.toLowerCase().includes(query) ||
        item.sub.toLowerCase().includes(query) ||
        (item.val && item.val.toString().toLowerCase().includes(query))
      ) {
        results.push({
          type: 'diagnostic',
          title: item.title,
          subtitle: item.sub,
          tab: item.tab,
          icon: `<svg class="spotlight-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.59 4.59A2 2 0 1 1 11 8H2m10.59 11.41A2 2 0 1 1 14 16H2M16 12H2"/></svg>`
        });
      }
    });

    // 2. Search Local Storage Vault
    state.vaultItems.forEach(item => {
      const matchTitle = item.title.toLowerCase().includes(query);
      const matchContent = item.content.toLowerCase().includes(query);
      const matchTags = item.tags.some(tag => tag.toLowerCase().includes(query));
      
      if (matchTitle || matchContent || matchTags) {
        results.push({
          type: 'vault',
          id: item.id,
          title: item.title,
          subtitle: item.content.length > 50 ? item.content.substring(0, 50) + '...' : item.content,
          tab: 'vault',
          icon: `<svg class="spotlight-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`
        });
      }
    });

    state.spotlightResults = results;

    if (results.length === 0) {
      elements.spotlightResults.innerHTML = `
        <div class="spotlight-no-results">
          <p>No results found for "${escapeHTML(query)}"</p>
        </div>
      `;
      return;
    }

    results.forEach((item, index) => {
      const itemEl = document.createElement('div');
      itemEl.className = 'spotlight-item';
      itemEl.setAttribute('data-index', index);
      
      itemEl.innerHTML = `
        <div class="spotlight-item-left">
          ${item.icon}
          <div class="spotlight-item-info">
            <span class="spotlight-item-title">${escapeHTML(item.title)}</span>
            <span class="spotlight-item-subtitle">${escapeHTML(item.subtitle)}</span>
          </div>
        </div>
        <span class="spotlight-item-type">${item.type}</span>
      `;

      itemEl.addEventListener('click', () => {
        state.selectedSpotlightIndex = index;
        selectSpotlightItem();
      });

      elements.spotlightResults.appendChild(itemEl);
    });
  }

  function navigateSpotlight(direction) {
    const items = elements.spotlightResults.querySelectorAll('.spotlight-item');
    if (items.length === 0) return;

    if (state.selectedSpotlightIndex !== -1 && items[state.selectedSpotlightIndex]) {
      items[state.selectedSpotlightIndex].classList.remove('selected');
    }

    state.selectedSpotlightIndex += direction;

    if (state.selectedSpotlightIndex >= items.length) {
      state.selectedSpotlightIndex = 0;
    } else if (state.selectedSpotlightIndex < 0) {
      state.selectedSpotlightIndex = items.length - 1;
    }

    const selectedEl = items[state.selectedSpotlightIndex];
    if (selectedEl) {
      selectedEl.classList.add('selected');
      selectedEl.scrollIntoView({ block: 'nearest' });
    }
  }

  function selectSpotlightItem() {
    const item = state.spotlightResults[state.selectedSpotlightIndex];
    if (!item) return;

    closeSpotlight();
    switchTab(item.tab);
    
    if (item.type === 'vault' && item.id) {
      setTimeout(() => {
        elements.vaultListSearch.value = item.title;
        renderVaultItems();
        
        const elementsList = elements.vaultItemsList.children;
        if (elementsList.length > 0) {
          const itemEl = elementsList[0];
          itemEl.style.borderColor = 'var(--accent-indigo)';
          itemEl.style.boxShadow = '0 0 15px var(--accent-indigo-glow)';
          itemEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
          
          setTimeout(() => {
            itemEl.style.borderColor = '';
            itemEl.style.boxShadow = '';
          }, 3000);
        }
      }, 200);
    }
  }

  // ----------------------------------------------------
  // 10. SYSTEM FUN TIPS ROTATOR
  // ----------------------------------------------------
  function initFactRotator() {
    elements.nextFactBtn.addEventListener('click', () => {
      state.currentFactIndex = (state.currentFactIndex + 1) % state.facts.length;
      elements.systemFact.style.opacity = 0;
      setTimeout(() => {
        elements.systemFact.textContent = state.facts[state.currentFactIndex];
        elements.systemFact.style.opacity = 1;
      }, 200);
    });
    
    elements.systemFact.textContent = state.facts[0];
  }

  // ----------------------------------------------------
  // APPLICATION INIT
  // ----------------------------------------------------
  function init() {
    startClock();
    monitorConnection();
    initTabs();
    setupAuthEvents();
    checkAuth();
  }

  // Wake up application
  init();
});
