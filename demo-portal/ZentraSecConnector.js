class ZentraSecConnector {
  /**
   * @param {string} apiUrl       - ZentraSec backend base URL (e.g. http://localhost:8000)
   * @param {string} connectionId - Connection ID issued by the SOC dashboard
   * @param {string} secureToken  - Secure bearer token (never put in NEXT_PUBLIC_ env vars)
   */
  constructor(apiUrl, connectionId, secureToken) {
    this.apiUrl = apiUrl;
    this.connectionId = connectionId;
    this.secureToken = secureToken;
    this.userId = null;
    this.appId = "devhub-demo-portal"; // application identifier sent with every event
  }

  setUserId(userId) {
    this.userId = userId;
  }

  /**
   * Core event sender — matches the EventIngestRequest schema exactly.
   * Errors are swallowed server-side: ZentraSec is NEVER allowed to break the
   * calling application's login flow.
   */
  async sendEvent(eventType, metadata = {}) {
    console.log("[BROWSER TEST] sendEvent EXECUTED:", eventType);
    // Ensure a secure token is present before attempting to send any event
    if (!this.secureToken) {
      console.error('[ZentraSec] Secure Token is required to send security events.');
      // Show a UI message if possible – the SDK itself cannot manipulate the DOM,
      // but the caller (Demo‑Portal) can decide how to surface this error.
      return null;
    }

    console.log('[DEBUG ZENTRASEC] sendEvent called', 'event_type='+eventType);
    const payload = {
      connection_id: this.connectionId,
      timestamp: new Date().toISOString(),
      user_id: this.userId || "anonymous",
      source_ip: "", // real IP extracted server-side from request.client.host
      destination: this.appId,
      event_type: eventType,
      metadata: {
        app_id: this.appId,
        user_agent: navigator.userAgent,
        ...metadata,
      },
    };

    try {
      console.log(`[ZentraSec] Sending ${eventType} → ${this.apiUrl}/api/v1/events`);
      const response = await fetch(`${this.apiUrl}/api/v1/events`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.secureToken}`,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        // Log the HTTP status and backend error message for debugging (without leaking the token)
        console.error(`[ZentraSec] Event rejected: HTTP ${response.status}`);
        const errorBody = await response.text();
        console.error('[ZentraSec] Backend response:', errorBody);
        return null;
      }
      const result = await response.json();
      console.log(`[ZentraSec] Event accepted — score: ${result.anomaly_score}, risk: ${result.risk_band}`);
      return result;
    } catch (e) {
      // Network / CORS errors must never surface to the end user
      console.error("[ZentraSec] Delivery failed (ZentraSec unavailable):", e.message);
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // High-level event helpers — these are the methods called by index.html
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Called by DevHub when login FAILS.
   * Sends a LOGIN_FAILED event (recognised by rules_engine BASE_SCORES and
   * ENRICHMENT_EVENT_TYPES). Includes user identifier, failure reason, and
   * application context. Real source IP is captured by the backend.
   *
   * @param {string}      username      - Attempted username / email
   * @param {string|null} _targetUserId - Unused (kept for API compat)
   * @param {string}      reason        - Human-readable failure reason
   */
  async trackLoginFailure(username, _targetUserId = null, reason = "Invalid credentials") {
    console.log("[BROWSER TEST] trackLoginFailure EXECUTED");
    this.setUserId(username);
    console.log('[DEBUG ZENTRASEC] trackLoginFailure called', 'user:', username);
    return this.sendEvent("LOGIN_FAILED", {
      failure_reason: reason,
      method: "password",
      authentication_status: "FAILED",
    });
  }

  /**
   * Called by DevHub when login SUCCEEDS.
   */
  async trackLoginSuccess(username) {
    this.setUserId(username);
    return this.sendEvent("LOGIN_SUCCESS", {
      method: "password",
      authentication_status: "SUCCESS",
    });
  }

  /**
   * Called when a user accesses the admin panel (privilege escalation demo).
   */
  async trackPrivilegeAccess() {
    return this.sendEvent("PRIVILEGE_ACCESS", {
      resource: "/admin",
      action: "privilege_escalation_attempt",
    });
  }

  /**
   * Called when a large file / database is downloaded (data exfiltration demo).
   */
  async trackFileDownload(filename) {
    return this.sendEvent("LARGE_FILE_DOWNLOAD", {
      file: filename,
      action: "data_exfiltration_demo",
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lower-level helpers (kept for programmatic use)
  // ─────────────────────────────────────────────────────────────────────────

  async login(username, success, method = "password") {
    this.setUserId(username);
    return this.sendEvent(success ? "LOGIN_SUCCESS" : "LOGIN_FAILURE", { method });
  }

  async logout()                   { return this.sendEvent("LOGOUT"); }
  async updateProfile()            { return this.sendEvent("PROFILE_UPDATE"); }
  async accessAdminPanel()         { return this.sendEvent("PRIVILEGE_ACCESS", { resource: "/admin" }); }
  async downloadLargeFile(filename){ return this.sendEvent("LARGE_FILE_DOWNLOAD", { file: filename }); }
  async register(username)         { return this.sendEvent("USER_REGISTRATION", { username }); }
  async resetPassword(username)    { return this.sendEvent("PASSWORD_RESET_REQUEST", { username }); }
}

console.log("[BROWSER TEST] ZentraSecConnector.js LOADED");
