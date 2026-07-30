/**
 * SYNORIX Rules API Client
 * Example client for interacting with Rules Management API
 */

class SynorixRulesClient {
  constructor(baseURL = 'http://localhost:3001', apiKey = null) {
    this.baseURL = baseURL;
    this.apiKey = apiKey;
    this.token = null;
  }

  /**
   * Set authentication token
   */
  setToken(token) {
    this.token = token;
  }

  /**
   * Make API request
   */
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    try {
      const response = await fetch(url, {
        method: options.method || 'GET',
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Request failed:', error);
      throw error;
    }
  }

  /**
   * Get all rules overview
   */
  async getAllRules() {
    return this.request('/api/rules');
  }

  /**
   * Get IPS (DROP) rules
   */
  async getIPSRules() {
    return this.request('/api/rules/ips');
  }

  /**
   * Get IDS (ALERT) rules
   */
  async getIDSRules() {
    return this.request('/api/rules/ids');
  }

  /**
   * Create a new rule
   */
  async createRule(ruleData) {
    return this.request('/api/rules', {
      method: 'POST',
      body: ruleData
    });
  }

  /**
   * Update an existing rule
   */
  async updateRule(sid, updates) {
    return this.request(`/api/rules/${sid}`, {
      method: 'PUT',
      body: updates
    });
  }

  /**
   * Delete a rule
   */
  async deleteRule(sid) {
    return this.request(`/api/rules/${sid}`, {
      method: 'DELETE'
    });
  }

  /**
   * Search rules
   */
  async searchRules(query, type = null) {
    const params = new URLSearchParams({ query });
    if (type) params.append('type', type);
    return this.request(`/api/rules/search?${params}`);
  }

  /**
   * Manually trigger export
   */
  async exportRules() {
    return this.request('/api/rules/export', {
      method: 'POST'
    });
  }

  /**
   * Generate firewall rules
   */
  async generateFirewallRules() {
    return this.request('/api/firewall/generate', {
      method: 'POST'
    });
  }

  /**
   * Get firewall status
   */
  async getFirewallStatus() {
    return this.request('/api/firewall/status');
  }
}

// ============ EXAMPLE USAGE ============

/**
 * Example: Create IPS rule via API
 */
async function exampleCreateIPSRule() {
  const client = new SynorixRulesClient('http://localhost:3001');
  
  try {
    const result = await client.createRule({
      sid: 2000001,
      action: 'drop',
      protocol: 'tcp',
      source_ip: '$EXTERNAL_NET',
      source_port: 'any',
      direction: '->',
      dest_ip: '$HTTP_SERVERS',
      dest_port: '80,443',
      msg: 'Block SQL Injection Attack',
      flow: 'established,to_server',
      content: 'union',
      classtype: 'web-application-attack',
      priority: 1,
      category: 'sql-injection'
    });

    console.log('✅ Rule created:', result);
  } catch (error) {
    console.error('❌ Failed to create rule:', error);
  }
}

/**
 * Example: Get all IPS rules and display
 */
async function exampleListIPSRules() {
  const client = new SynorixRulesClient();

  try {
    const result = await client.getIPSRules();
    
    console.log(`📊 IPS Rules (Total: ${result.count})`);
    result.rules.forEach(rule => {
      console.log(`\n  SID: ${rule.sid}`);
      console.log(`  Message: ${rule.msg}`);
      console.log(`  Priority: ${rule.priority}`);
      console.log(`  Category: ${rule.category}`);
      console.log(`  Status: ${rule.enabled ? '✅ Enabled' : '⏸️ Disabled'}`);
    });
  } catch (error) {
    console.error('❌ Failed to list IPS rules:', error);
  }
}

/**
 * Example: Search rules
 */
async function exampleSearchRules() {
  const client = new SynorixRulesClient();

  try {
    // Search for SQL injection rules
    const results = await client.searchRules('sql', 'ips');
    
    console.log(`🔍 Search results for "sql" (IPS only):`);
    console.log(`Found: ${results.results} rules`);
    
    results.rules.forEach(rule => {
      console.log(`\n  ${rule.sid}: ${rule.msg}`);
    });
  } catch (error) {
    console.error('❌ Failed to search rules:', error);
  }
}

/**
 * Example: Update rule priority
 */
async function exampleUpdateRule() {
  const client = new SynorixRulesClient();

  try {
    const result = await client.updateRule(2000001, {
      priority: 2,
      msg: 'Updated SQL Injection Detection',
      enabled: 1
    });

    console.log('✅ Rule updated:', result);
  } catch (error) {
    console.error('❌ Failed to update rule:', error);
  }
}

/**
 * Example: Get firewall status
 */
async function exampleGetFirewallStatus() {
  const client = new SynorixRulesClient();

  try {
    const status = await client.getFirewallStatus();
    
    console.log('🔥 Firewall Status:');
    console.log(`Status: ${status.status}`);
    console.log(`Firewall Type: ${status.firewall}`);
    console.log(`Last Generated: ${status.lastGenerated}`);
    console.log(`\nCapabilities:`);
    status.capabilities.forEach(cap => {
      console.log(`  ✓ ${cap}`);
    });
  } catch (error) {
    console.error('❌ Failed to get firewall status:', error);
  }
}

/**
 * Example: Full rule lifecycle
 */
async function exampleFullRuleLifecycle() {
  const client = new SynorixRulesClient();

  try {
    console.log('📋 Full Rule Lifecycle Example\n');

    // 1. Create rule
    console.log('1️⃣  Creating new rule...');
    const created = await client.createRule({
      sid: 2000999,
      action: 'drop',
      protocol: 'tcp',
      source_ip: '$EXTERNAL_NET',
      source_port: 'any',
      direction: '->',
      dest_ip: '$HTTP_SERVERS',
      dest_port: '80',
      msg: 'Test Rule for Lifecycle',
      classtype: 'web-application-attack',
      priority: 3,
      category: 'test-rule'
    });
    console.log(`✅ Created: ${created.message}\n`);

    // 2. Search for the rule
    console.log('2️⃣  Searching for the new rule...');
    const searched = await client.searchRules('lifecycle', 'ips');
    console.log(`✅ Found ${searched.results} rules\n`);

    // 3. Update the rule
    console.log('3️⃣  Updating rule priority...');
    const updated = await client.updateRule(2000999, {
      priority: 1,
      enabled: 1
    });
    console.log(`✅ Updated: ${updated.message}\n`);

    // 4. Check firewall status
    console.log('4️⃣  Checking firewall status...');
    const status = await client.getFirewallStatus();
    console.log(`✅ Firewall is ${status.status}\n`);

    // 5. Trigger export
    console.log('5️⃣  Exporting rules...');
    const exported = await client.exportRules();
    console.log(`✅ Export: ${exported.message}\n`);

    // 6. Delete the rule
    console.log('6️⃣  Deleting test rule...');
    const deleted = await client.deleteRule(2000999);
    console.log(`✅ Deleted: ${deleted.message}\n`);

    console.log('🎉 Lifecycle complete!');
  } catch (error) {
    console.error('❌ Lifecycle failed:', error);
  }
}

/**
 * Example: Batch rule creation
 */
async function exampleBatchRuleCreation() {
  const client = new SynorixRulesClient();

  const rules = [
    {
      sid: 2001001,
      action: 'drop',
      protocol: 'tcp',
      msg: 'Detect XXE Attacks',
      content: 'DOCTYPE',
      category: 'xxe-detection'
    },
    {
      sid: 2001002,
      action: 'drop',
      protocol: 'tcp',
      msg: 'Detect Path Traversal',
      content: '../',
      category: 'path-traversal'
    },
    {
      sid: 2001003,
      action: 'alert',
      protocol: 'tcp',
      msg: 'Detect Admin Panel Access',
      content: '/admin',
      category: 'admin-access'
    }
  ];

  try {
    console.log('📦 Creating batch of rules...\n');

    for (const ruleData of rules) {
      const fullRule = {
        source_ip: '$EXTERNAL_NET',
        source_port: 'any',
        direction: '->',
        dest_ip: '$HTTP_SERVERS',
        dest_port: '80,443',
        classtype: 'web-application-attack',
        priority: 2,
        ...ruleData
      };

      try {
        const result = await client.createRule(fullRule);
        console.log(`✅ ${ruleData.msg} (SID: ${ruleData.sid})`);
      } catch (error) {
        console.log(`❌ Failed to create ${ruleData.msg}`);
      }
    }

    console.log('\n✅ Batch creation complete!');
  } catch (error) {
    console.error('❌ Batch creation failed:', error);
  }
}

// Export for use in browser or Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SynorixRulesClient,
    exampleCreateIPSRule,
    exampleListIPSRules,
    exampleSearchRules,
    exampleUpdateRule,
    exampleGetFirewallStatus,
    exampleFullRuleLifecycle,
    exampleBatchRuleCreation
  };
}
