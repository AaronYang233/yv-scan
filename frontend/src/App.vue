<template>
  <div id="app">
    <div class="card">
      <div class="hdr">
        <div class="logo">🛡️</div>
        <div>
          <div>安全漏洞扫描系统</div>
          <div>Security Vulnerability Scanner</div>
        </div>
      </div>

      <div class="body">
        <div class="scan-section">
          <h3>创建扫描任务</h3>
          <form @submit.prevent="createScan">
            <div class="form-row">
              <div class="form-group">
                <label>扫描类型</label>
                <select v-model="scanForm.type" required>
                  <option value="">请选择扫描类型</option>
                  <option value="image">Docker 镜像</option>
                  <option value="repo">GitHub 仓库</option>
                </select>
              </div>
              <div class="form-group flex-grow">
                <label>{{ scanForm.type === 'repo' ? 'GitHub 仓库地址' : '镜像地址' }}</label>
                <input 
                  v-model="scanForm.target" 
                  :placeholder="scanForm.type === 'repo' ? 'https://github.com/user/repo' : 'nginx:latest'" 
                  required 
                />
              </div>
            </div>
            <button type="submit" :disabled="loading || !scanForm.type">
              {{ loading ? '创建中...' : '开始扫描' }}
            </button>
          </form>
        </div>

        <div class="divider"></div>

        <div class="history-section">
          <div class="section-header">
            <h3>扫描历史</h3>
            <button class="refresh-btn" @click="refreshScans">
              <span class="refresh-icon">⟳</span> 刷新
            </button>
          </div>

          <div v-if="scans.length === 0" class="empty">
            <div class="empty-icon">📋</div>
            <p>暂无扫描记录</p>
          </div>

          <div v-else class="scan-list">
            <div 
              v-for="scan in scans" 
              :key="scan.task_id" 
              class="scan-item"
              @click="viewScanDetail(scan.task_id)"
            >
              <div class="scan-item-header">
                <div class="scan-type-badge" :class="scan.type">
                  {{ scan.type === 'image' ? '镜像' : '仓库' }}
                </div>
                <div class="scan-status-badge" :class="scan.status">
                  {{ getStatusText(scan.status) }}
                </div>
              </div>
              
              <div class="scan-target">{{ scan.target }}</div>
              
              <div v-if="scan.stats && scan.status === 'completed'" class="scan-stats">
                <div class="stat-item critical" v-if="scan.stats.critical > 0">
                  <span class="stat-label">严重</span>
                  <span class="stat-value">{{ scan.stats.critical }}</span>
                </div>
                <div class="stat-item high" v-if="scan.stats.high > 0">
                  <span class="stat-label">高危</span>
                  <span class="stat-value">{{ scan.stats.high }}</span>
                </div>
                <div class="stat-item medium" v-if="scan.stats.medium > 0">
                  <span class="stat-label">中危</span>
                  <span class="stat-value">{{ scan.stats.medium }}</span>
                </div>
                <div class="stat-item low" v-if="scan.stats.low > 0">
                  <span class="stat-label">低危</span>
                  <span class="stat-value">{{ scan.stats.low }}</span>
                </div>
                <div v-if="scan.stats.total === 0" class="no-vuln">
                  ✓ 未发现漏洞
                </div>
              </div>
              
              <div class="scan-time">{{ formatDate(scan.created_at) }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 详情弹窗 -->
    <div v-if="selectedScan" class="modal-overlay" @click="selectedScan = null">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h2>扫描详情</h2>
          <button class="close-btn" @click="selectedScan = null">×</button>
        </div>
        
        <div class="modal-body">
          <div class="detail-item">
            <span class="detail-label">扫描目标：</span>
            <span class="detail-value">{{ selectedScan.target }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">扫描类型：</span>
            <span class="detail-value">{{ selectedScan.type === 'image' ? 'Docker 镜像' : 'GitHub 仓库' }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">状态：</span>
            <span class="scan-status-badge" :class="selectedScan.status">
              {{ getStatusText(selectedScan.status) }}
            </span>
          </div>
          <div class="detail-item">
            <span class="detail-label">创建时间：</span>
            <span class="detail-value">{{ formatDate(selectedScan.created_at) }}</span>
          </div>

          <div v-if="selectedScan.error" class="error-box">
            <strong>错误信息：</strong>{{ selectedScan.error }}
          </div>

          <div v-if="selectedScan.stats && selectedScan.status === 'completed'" class="vuln-summary">
            <h3>漏洞统计</h3>
            <div class="stats-grid">
              <div class="stat-card critical">
                <div class="stat-number">{{ selectedScan.stats.critical }}</div>
                <div class="stat-text">严重漏洞</div>
              </div>
              <div class="stat-card high">
                <div class="stat-number">{{ selectedScan.stats.high }}</div>
                <div class="stat-text">高危漏洞</div>
              </div>
              <div class="stat-card medium">
                <div class="stat-number">{{ selectedScan.stats.medium }}</div>
                <div class="stat-text">中危漏洞</div>
              </div>
              <div class="stat-card low">
                <div class="stat-number">{{ selectedScan.stats.low }}</div>
                <div class="stat-text">低危漏洞</div>
              </div>
            </div>
          </div>

          <div v-if="selectedScan.result && selectedScan.status === 'completed'" class="vuln-details">
            <h3>漏洞详情</h3>
            <div v-for="(result, idx) in selectedScan.result.Results" :key="idx">
              <h4>{{ result.Target }}</h4>
              <div v-if="result.Vulnerabilities && result.Vulnerabilities.length > 0">
                <div class="vuln-table">
                  <div class="vuln-row vuln-header">
                    <div class="vuln-cell">漏洞编号</div>
                    <div class="vuln-cell">严重程度</div>
                    <div class="vuln-cell">包名</div>
                    <div class="vuln-cell">版本</div>
                  </div>
                  <div 
                    v-for="vuln in result.Vulnerabilities.slice(0, 20)" 
                    :key="vuln.VulnerabilityID" 
                    class="vuln-row"
                  >
                    <div class="vuln-cell">{{ vuln.VulnerabilityID }}</div>
                    <div class="vuln-cell">
                      <span class="severity-badge" :class="vuln.Severity.toLowerCase()">
                        {{ getSeverityText(vuln.Severity) }}
                      </span>
                    </div>
                    <div class="vuln-cell">{{ vuln.PkgName }}</div>
                    <div class="vuln-cell">{{ vuln.InstalledVersion }}</div>
                  </div>
                  <div v-if="result.Vulnerabilities.length > 20" class="more-info">
                    还有 {{ result.Vulnerabilities.length - 20 }} 个漏洞未显示
                  </div>
                </div>
              </div>
              <div v-else class="no-vuln-message">
                ✓ 未发现漏洞
              </div>
            </div>
          </div>

          <div class="modal-footer">
            <button @click="downloadReport(selectedScan.task_id)" v-if="selectedScan.status === 'completed'">
              下载完整报告
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default {
  data() {
    return {
      scanForm: {
        type: '',
        target: ''
      },
      scans: [],
      selectedScan: null,
      loading: false,
      autoRefresh: null
    }
  },
  mounted() {
    this.refreshScans()
    this.autoRefresh = setInterval(() => {
      this.refreshScans()
    }, 5000)
  },
  beforeUnmount() {
    if (this.autoRefresh) {
      clearInterval(this.autoRefresh)
    }
  },
  methods: {
    async createScan() {
      this.loading = true
      try {
        const response = await axios.post(`${API_URL}/api/scan`, {
          type: this.scanForm.type,
          target: this.scanForm.target
        })
        
        alert('扫描任务创建成功！')
        this.scanForm.target = ''
        this.refreshScans()
      } catch (error) {
        alert('创建失败：' + (error.response?.data?.error || error.message))
      } finally {
        this.loading = false
      }
    },
    
    async refreshScans() {
      try {
        const response = await axios.get(`${API_URL}/api/scans`)
        this.scans = response.data.scans
      } catch (error) {
        console.error('获取扫描列表失败:', error)
      }
    },
    
    async viewScanDetail(taskId) {
      try {
        const response = await axios.get(`${API_URL}/api/scan/${taskId}`)
        this.selectedScan = response.data
      } catch (error) {
        alert('获取详情失败：' + error.message)
      }
    },
    
    downloadReport(taskId) {
      window.open(`${API_URL}/api/scan/${taskId}/report`, '_blank')
    },
    
    getStatusText(status) {
      const statusMap = {
        'pending': '等待中',
        'running': '扫描中',
        'completed': '已完成',
        'failed': '失败',
        'timeout': '超时'
      }
      return statusMap[status] || status
    },
    
    getSeverityText(severity) {
      const map = {
        'CRITICAL': '严重',
        'HIGH': '高危',
        'MEDIUM': '中危',
        'LOW': '低危'
      }
      return map[severity] || severity
    },
    
    formatDate(dateString) {
      const date = new Date(dateString)
      return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      })
    }
  }
}
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  background: #f3f6f9;
  color: #111827;
  line-height: 1.6;
}

#app {
  max-width: 1200px;
  margin: 28px auto;
  padding: 0 20px;
}

.card {
  background: #fff;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
}

.hdr {
  padding: 18px 22px;
  display: flex;
  gap: 12px;
  align-items: center;
  background: #50bfff;
  color: #fff;
}

.logo {
  font-size: 44px;
  line-height: 1;
}

.hdr > div {
  display: flex;
  flex-direction: column;
}

.hdr > div > div:first-child {
  font-weight: 700;
  font-size: 18px;
}

.hdr > div > div:last-child {
  font-size: 13px;
  color: #eaf6ff;
  margin-top: 2px;
}

.body {
  padding: 22px;
}

.scan-section h3,
.history-section h3 {
  font-size: 16px;
  margin-bottom: 16px;
  color: #111827;
  font-weight: 600;
}

.form-row {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}

.form-group {
  display: flex;
  flex-direction: column;
  min-width: 180px;
}

.form-group.flex-grow {
  flex: 1;
}

label {
  font-size: 14px;
  margin-bottom: 6px;
  color: #374151;
  font-weight: 500;
}

input, select {
  padding: 10px 12px;
  border: 1px solid #d1d5db;
  border-radius: 4px;
  font-size: 14px;
  font-family: inherit;
  transition: border-color 0.2s;
}

input:focus, select:focus {
  outline: none;
  border-color: #50bfff;
}

button {
  background: #50bfff;
  color: white;
  border: none;
  padding: 10px 24px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: background 0.2s;
}

button:hover:not(:disabled) {
  background: #3da5e0;
}

button:disabled {
  background: #9ca3af;
  cursor: not-allowed;
}

.divider {
  height: 1px;
  background: #e5e7eb;
  margin: 28px 0;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.refresh-btn {
  background: #f3f4f6;
  color: #374151;
  padding: 6px 12px;
  font-size: 13px;
  display: flex;
  align-items: center;
  gap: 4px;
}

.refresh-btn:hover {
  background: #e5e7eb;
}

.refresh-icon {
  font-size: 16px;
}

.empty {
  text-align: center;
  padding: 60px 20px;
  color: #9ca3af;
}

.empty-icon {
  font-size: 48px;
  margin-bottom: 12px;
}

.scan-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.scan-item {
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s;
}

.scan-item:hover {
  border-color: #50bfff;
  box-shadow: 0 2px 8px rgba(80, 191, 255, 0.1);
}

.scan-item-header {
  display: flex;
  gap: 8px;
  margin-bottom: 10px;
}

.scan-type-badge {
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.scan-type-badge.image {
  background: #dbeafe;
  color: #1e40af;
}

.scan-type-badge.repo {
  background: #f3e8ff;
  color: #6b21a8;
}

.scan-status-badge {
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.scan-status-badge.pending {
  background: #fef3c7;
  color: #92400e;
}

.scan-status-badge.running {
  background: #dbeafe;
  color: #1e40af;
}

.scan-status-badge.completed {
  background: #d1fae5;
  color: #065f46;
}

.scan-status-badge.failed,
.scan-status-badge.timeout {
  background: #fee2e2;
  color: #991b1b;
}

.scan-target {
  font-size: 14px;
  color: #111827;
  margin-bottom: 10px;
  font-weight: 500;
}

.scan-stats {
  display: flex;
  gap: 12px;
  margin-bottom: 8px;
  flex-wrap: wrap;
}

.stat-item {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

.stat-item.critical {
  background: #fee2e2;
  color: #991b1b;
}

.stat-item.high {
  background: #fed7aa;
  color: #9a3412;
}

.stat-item.medium {
  background: #fef3c7;
  color: #92400e;
}

.stat-item.low {
  background: #e0e7ff;
  color: #3730a3;
}

.stat-label {
  font-weight: 500;
}

.stat-value {
  font-weight: 700;
}

.no-vuln {
  color: #059669;
  font-size: 13px;
  font-weight: 500;
}

.scan-time {
  font-size: 12px;
  color: #6b7280;
}

/* 弹窗样式 */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: white;
  border-radius: 8px;
  max-width: 900px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
}

.modal-header {
  padding: 20px 24px;
  border-bottom: 1px solid #e5e7eb;
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  background: white;
  z-index: 1;
}

.modal-header h2 {
  font-size: 18px;
  font-weight: 600;
}

.close-btn {
  background: none;
  color: #6b7280;
  font-size: 28px;
  padding: 0;
  width: 32px;
  height: 32px;
  line-height: 1;
}

.close-btn:hover {
  background: #f3f4f6;
  color: #111827;
}

.modal-body {
  padding: 24px;
}

.detail-item {
  margin-bottom: 14px;
  font-size: 14px;
}

.detail-label {
  color: #6b7280;
  margin-right: 8px;
}

.detail-value {
  color: #111827;
  font-weight: 500;
}

.error-box {
  background: #fef2f2;
  border: 1px solid #fecaca;
  border-radius: 4px;
  padding: 12px;
  margin: 16px 0;
  color: #991b1b;
  font-size: 14px;
}

.vuln-summary {
  margin-top: 24px;
}

.vuln-summary h3 {
  font-size: 16px;
  margin-bottom: 16px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
}

.stat-card {
  padding: 16px;
  border-radius: 6px;
  text-align: center;
}

.stat-card.critical {
  background: #fee2e2;
}

.stat-card.high {
  background: #fed7aa;
}

.stat-card.medium {
  background: #fef3c7;
}

.stat-card.low {
  background: #e0e7ff;
}

.stat-number {
  font-size: 32px;
  font-weight: 700;
  margin-bottom: 4px;
}

.stat-card.critical .stat-number {
  color: #991b1b;
}

.stat-card.high .stat-number {
  color: #9a3412;
}

.stat-card.medium .stat-number {
  color: #92400e;
}

.stat-card.low .stat-number {
  color: #3730a3;
}

.stat-text {
  font-size: 13px;
  color: #6b7280;
  font-weight: 500;
}

.vuln-details {
  margin-top: 24px;
}

.vuln-details h3,
.vuln-details h4 {
  font-size: 16px;
  margin-bottom: 12px;
  color: #111827;
}

.vuln-details h4 {
  font-size: 14px;
  margin-top: 20px;
  color: #374151;
}

.vuln-table {
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  overflow: hidden;
  margin-bottom: 16px;
}

.vuln-row {
  display: grid;
  grid-template-columns: 2fr 1fr 2fr 1.5fr;
  border-bottom: 1px solid #e5e7eb;
}

.vuln-row:last-child {
  border-bottom: none;
}

.vuln-header {
  background: #f9fafb;
  font-weight: 600;
}

.vuln-cell {
  padding: 10px 12px;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.severity-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}

.severity-badge.critical {
  background: #fee2e2;
  color: #991b1b;
}

.severity-badge.high {
  background: #fed7aa;
  color: #9a3412;
}

.severity-badge.medium {
  background: #fef3c7;
  color: #92400e;
}

.severity-badge.low {
  background: #e0e7ff;
  color: #3730a3;
}

.more-info {
  padding: 12px;
  text-align: center;
  background: #f9fafb;
  color: #6b7280;
  font-size: 13px;
}

.no-vuln-message {
  padding: 20px;
  text-align: center;
  background: #f0fdf4;
  color: #059669;
  border-radius: 6px;
  font-weight: 500;
}

.modal-footer {
  padding: 16px 24px;
  border-top: 1px solid #e5e7eb;
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  position: sticky;
  bottom: 0;
  background: white;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .form-row {
    flex-direction: column;
  }
  
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .vuln-row {
    grid-template-columns: 1fr;
  }
  
  .vuln-cell {
    border-bottom: 1px solid #f3f4f6;
  }
  
  .vuln-cell:last-child {
    border-bottom: none;
  }
  
  .vuln-header .vuln-cell:not(:first-child) {
    display: none;
  }
  
  .scan-stats {
    gap: 8px;
  }
}
</style>
