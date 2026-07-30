const { getRecentRequests, getRequestsFromDB, getRequestStats } = require('../middleware/requestLogger');

/**
 * Get paginated request logs with filtering
 */
async function getRequestLogs(req, res) {
  try {
    const {
      page = 1,
      limit = 50,
      method,
      status,
      blocked,
      compressed,
      clientIP,
      startTime,
      endTime,
      source = 'db' // 'cache' for recent, 'db' for historical
    } = req.query;

    // Parse query parameters
    const pageNum = parseInt(page, 10);
    const limitNum = Math.min(parseInt(limit, 10), 1000); // Cap at 1000
    const filters = {
      method,
      status: status ? parseInt(status, 10) : null,
      blocked: blocked === 'true',
      compressed: compressed === 'true',
      clientIP,
      startTime,
      endTime
    };

    // Remove undefined filters
    Object.keys(filters).forEach(key => {
      if (filters[key] === null || filters[key] === undefined || filters[key] === '') {
        delete filters[key];
      }
    });

    let result;

    if (source === 'cache') {
      // Get from in-memory cache (faster, recent data only)
      const recentRequests = getRecentRequests(limitNum);
      
      // Apply client-side filtering for cache
      let filtered = recentRequests;
      
      if (filters.method) {
        filtered = filtered.filter(req => req.method === filters.method);
      }
      
      if (filters.status) {
        filtered = filtered.filter(req => req.responseStatus === filters.status);
      }
      
      if (filters.blocked) {
        filtered = filtered.filter(req => 
          req.wafAction !== 'allowed' || req.suricataAction !== 'allowed'
        );
      }
      
      if (filters.compressed) {
        filtered = filtered.filter(req => req.compressed);
      }
      
      if (filters.clientIP) {
        filtered = filtered.filter(req => req.clientIP === filters.clientIP);
      }

      // Paginate filtered results
      const startIndex = (pageNum - 1) * limitNum;
      const endIndex = startIndex + limitNum;
      const paginatedData = filtered.slice(startIndex, endIndex);

      result = {
        data: paginatedData,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total: filtered.length,
          totalPages: Math.ceil(filtered.length / limitNum)
        },
        source: 'cache'
      };
    } else {
      // Get from database (slower, but complete historical data)
      result = await getRequestsFromDB(pageNum, limitNum, filters);
      result.source = 'database';
    }

    res.json(result);

  } catch (error) {
    console.error('Error fetching request logs:', error);
    res.status(500).json({ 
      error: 'Failed to fetch request logs',
      message: error.message 
    });
  }
}

/**
 * Get request statistics
 */
async function getRequestStatistics(req, res) {
  try {
    const { timeframe = '24h' } = req.query;

    // Validate timeframe
    const validTimeframes = ['1h', '24h', '7d', '30d'];
    if (!validTimeframes.includes(timeframe)) {
      return res.status(400).json({ 
        error: 'Invalid timeframe',
        validOptions: validTimeframes 
      });
    }

    const stats = await getRequestStats(timeframe);

    // Add additional computed metrics
    const computedStats = {
      ...stats,
      blockedRequests: (stats.wafBlocked || 0) + (stats.suricataBlocked || 0),
      errorRate: stats.totalRequests > 0 
        ? ((stats.errorRequests || 0) / stats.totalRequests * 100).toFixed(2)
        : 0,
      blockRate: stats.totalRequests > 0 
        ? (((stats.wafBlocked || 0) + (stats.suricataBlocked || 0)) / stats.totalRequests * 100).toFixed(2)
        : 0,
      compressionRate: stats.totalRequests > 0
        ? ((stats.compressedRequests || 0) / stats.totalRequests * 100).toFixed(2)
        : 0,
      timeframe
    };

    res.json(computedStats);

  } catch (error) {
    console.error('Error fetching request statistics:', error);
    res.status(500).json({ 
      error: 'Failed to fetch statistics',
      message: error.message 
    });
  }
}

/**
 * Get top IPs by request count
 */
async function getTopIPs(req, res) {
  try {
    const { limit = 10, timeframe = '24h' } = req.query;

    let timeCondition = '';
    switch (timeframe) {
      case '1h':
        timeCondition = "AND timestamp >= datetime('now', '-1 hour')";
        break;
      case '24h':
        timeCondition = "AND timestamp >= datetime('now', '-1 day')";
        break;
      case '7d':
        timeCondition = "AND timestamp >= datetime('now', '-7 days')";
        break;
      case '30d':
        timeCondition = "AND timestamp >= datetime('now', '-30 days')";
        break;
    }

    const query = `
      SELECT 
        client_ip,
        COUNT(*) as requestCount,
        COUNT(CASE WHEN response_status >= 400 THEN 1 END) as errorCount,
        COUNT(CASE WHEN waf_action != 'allowed' OR suricata_action != 'allowed' THEN 1 END) as blockedCount,
        AVG(response_time) as avgResponseTime
      FROM request_logs 
      WHERE 1=1 ${timeCondition}
      GROUP BY client_ip 
      ORDER BY requestCount DESC 
      LIMIT ?
    `;

    // This would need to be executed with the database
    // For now, return mock data structure
    const topIPs = [
      {
        client_ip: '192.168.1.100',
        requestCount: 245,
        errorCount: 12,
        blockedCount: 3,
        avgResponseTime: 0.156
      }
    ];

    res.json({
      timeframe,
      limit: parseInt(limit, 10),
      data: topIPs
    });

  } catch (error) {
    console.error('Error fetching top IPs:', error);
    res.status(500).json({ 
      error: 'Failed to fetch top IPs',
      message: error.message 
    });
  }
}

/**
 * Get request trends (hourly/daily breakdown)
 */
async function getRequestTrends(req, res) {
  try {
    const { timeframe = '24h', granularity = 'hour' } = req.query;

    // Mock trend data for now
    const trends = {
      timeframe,
      granularity,
      data: Array.from({ length: 24 }, (_, i) => ({
        timestamp: new Date(Date.now() - (23 - i) * 60 * 60 * 1000).toISOString(),
        totalRequests: Math.floor(Math.random() * 100) + 50,
        blockedRequests: Math.floor(Math.random() * 10),
        compressedRequests: Math.floor(Math.random() * 30) + 10,
        avgResponseTime: (Math.random() * 0.5 + 0.1).toFixed(3)
      }))
    };

    res.json(trends);

  } catch (error) {
    console.error('Error fetching request trends:', error);
    res.status(500).json({ 
      error: 'Failed to fetch trends',
      message: error.message 
    });
  }
}

/**
 * Search request logs
 */
async function searchRequestLogs(req, res) {
  try {
    const {
      query = '',
      page = 1,
      limit = 50,
      searchField = 'all' // 'url', 'ip', 'userAgent', 'all'
    } = req.query;

    if (!query.trim()) {
      return res.status(400).json({ 
        error: 'Search query is required' 
      });
    }

    // This would need actual database search implementation
    // For now, return mock results
    const searchResults = {
      query,
      searchField,
      data: [],
      pagination: {
        page: parseInt(page, 10),
        limit: parseInt(limit, 10),
        total: 0,
        totalPages: 0
      }
    };

    res.json(searchResults);

  } catch (error) {
    console.error('Error searching request logs:', error);
    res.status(500).json({ 
      error: 'Failed to search logs',
      message: error.message 
    });
  }
}

/**
 * Export request logs (CSV format)
 */
async function exportRequestLogs(req, res) {
  try {
    const { 
      format = 'csv',
      startTime,
      endTime,
      filters 
    } = req.query;

    if (format !== 'csv') {
      return res.status(400).json({ 
        error: 'Only CSV format is currently supported' 
      });
    }

    // Set CSV headers
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=request_logs.csv');

    // CSV header
    const csvHeader = 'Timestamp,Method,URL,Client IP,Status,Response Time,Compressed,WAF Action,Suricata Action\n';
    res.write(csvHeader);

    // This would stream actual data from database
    // For now, send empty CSV with headers
    res.end();

  } catch (error) {
    console.error('Error exporting request logs:', error);
    res.status(500).json({ 
      error: 'Failed to export logs',
      message: error.message 
    });
  }
}

module.exports = {
  getRequestLogs,
  getRequestStatistics,
  getTopIPs,
  getRequestTrends,
  searchRequestLogs,
  exportRequestLogs
};