const API_BASE = "http://localhost:8000/api";

function getHeaders() {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const token = localStorage.getItem("token");
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function request(endpoint: string, options: RequestInit = {}) {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      ...getHeaders(),
      ...options.headers,
    },
  });

  if (response.status === 401) {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("username");
    window.dispatchEvent(new Event("auth-change"));
  }

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || "Request failed");
  }

  // Handle binary/file streaming (like PDF reports)
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/pdf")) {
    return response.blob();
  }

  return response.json();
}

export const api = {
  // Auth
  login: async (username: string, password: string) => {
    const data = await request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    localStorage.setItem("token", data.access_token);
    localStorage.setItem("role", data.role);
    localStorage.setItem("username", data.username);
    window.dispatchEvent(new Event("auth-change"));
    return data;
  },
  
  logout: () => {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("username");
    window.dispatchEvent(new Event("auth-change"));
  },
  
  isAuthenticated: () => {
    return !!localStorage.getItem("token");
  },
  
  getUser: () => {
    return {
      username: localStorage.getItem("username"),
      role: localStorage.getItem("role")
    };
  },

  // Dashboard
  getStats: () => request("/dashboard/stats"),
  getMitreMatrix: () => request("/dashboard/mitre-matrix"),
  getTimeline: () => request("/dashboard/timeline"),

  // Incidents
  getIncidents: (filters?: { status?: string; severity?: string; analyst?: string }) => {
    let query = "";
    if (filters) {
      const params = new URLSearchParams();
      if (filters.status) params.append("status", filters.status);
      if (filters.severity) params.append("severity", filters.severity);
      if (filters.analyst) params.append("analyst", filters.analyst);
      query = `?${params.toString()}`;
    }
    return request(`/incidents${query}`);
  },
  
  getIncident: (id: number) => request(`/incidents/${id}`),
  
  updateIncident: (id: number, data: any) => request(`/incidents/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  }),
  
  addComment: (id: number, content: string) => {
    const username = localStorage.getItem("username") || "Analyst";
    return request(`/incidents/${id}/comments?author=${encodeURIComponent(username)}`, {
      method: "POST",
      body: JSON.stringify({ content }),
    });
  },
  
  triggerAiAnalysis: (id: number) => request(`/incidents/${id}/analyze-ai`, {
    method: "POST",
  }),
  
  downloadReport: async (id: number) => {
    const blob = await request(`/incidents/${id}/report`);
    const downloadUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = downloadUrl;
    a.download = `incident_${id}_report.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(downloadUrl);
  },

  // Alerts & Hunting
  getAlerts: (filters?: { severity?: string; host?: string; unassigned?: boolean }) => {
    let query = "";
    if (filters) {
      const params = new URLSearchParams();
      if (filters.severity) params.append("severity", filters.severity);
      if (filters.host) params.append("host", filters.host);
      if (filters.unassigned) params.append("unassigned", String(filters.unassigned));
      query = `?${params.toString()}`;
    }
    return request(`/alerts${query}`);
  },
  
  huntLogs: (params: { search?: string; host?: string; user?: string; source?: string; event_id?: number; limit?: number }) => {
    const queryParams = new URLSearchParams();
    if (params.search) queryParams.append("search", params.search);
    if (params.host) queryParams.append("host", params.host);
    if (params.user) queryParams.append("user", params.user);
    if (params.source) queryParams.append("source", params.source);
    if (params.event_id !== undefined) queryParams.append("event_id", String(params.event_id));
    if (params.limit !== undefined) queryParams.append("limit", String(params.limit));
    
    return request(`/hunting/logs?${queryParams.toString()}`);
  },

  // Rules
  getRules: () => request("/rules"),
  
  createRule: (rule: any) => request("/rules", {
    method: "POST",
    body: JSON.stringify(rule),
  }),
  
  toggleRule: (id: string) => request(`/rules/${id}/toggle`, {
    method: "PUT",
  }),
  
  deleteRule: (id: string) => request(`/rules/${id}`, {
    method: "DELETE",
  }),

  // Simulator
  triggerSimulation: (scenario: string) => request(`/simulator/trigger?scenario=${scenario}`, {
    method: "POST",
  }),
  
  resetSimulation: () => request("/simulator/reset", {
    method: "POST",
  }),

  // Threat Intel
  enrichIoc: (ioc: string) => request(`/threat-intel/enrich?ioc=${encodeURIComponent(ioc)}`)
};
