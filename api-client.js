/**
 * NetView API Client
 * Handles communication with the backend REST API
 */

class NetViewAPI {
  constructor(baseURL = 'http://localhost:8080') {
    this.baseURL = baseURL;
    this.lastScan = null;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  /**
   * Run a new network scan
   */
  async scan(subnets = null, options = {}) {
    let endpoint = '/scan';
    const params = new URLSearchParams();

    if (subnets && Array.isArray(subnets)) {
      subnets.forEach(s => params.append('subnet', s));
    }

    if (options.no_icmp) params.append('no_icmp', '1');
    if (options.no_snmp) params.append('no_snmp', '1');
    if (options.format) params.append('format', options.format);

    if (params.toString()) {
      endpoint += '?' + params.toString();
    }

    const data = await this.request(endpoint);
    this.lastScan = data;
    return data;
  }

  /**
   * Get all devices from last scan
   */
  async getDevices(type = null) {
    let endpoint = '/devices';
    if (type) {
      endpoint += '?type=' + encodeURIComponent(type);
    }

    try {
      const data = await this.request(endpoint);
      return data.devices || [];
    } catch (e) {
      console.warn('No scan data available:', e.message);
      return [];
    }
  }

  /**
   * Get details for a specific device
   */
  async getDevice(ip) {
    return this.request(`/device/${encodeURIComponent(ip)}`);
  }

  /**
   * Get scan info
   */
  async getScanInfo() {
    const data = await this.request('/scan');
    return data.scan_info;
  }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = NetViewAPI;
}
