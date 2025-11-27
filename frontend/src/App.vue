<!-- frontend/src/App.vue -->
<template>
  <div id="app">
    <header>
      <h1>🔍 Trivy Scanner Service</h1>
    </header>
    
    <main>
      <div class="scan-form">
        <h2>Create New Scan</h2>
        <form @submit.prevent="createScan">
          <div class="form-group">
            <label>Scan Type:</label>
            <select v-model="scanForm.type">
              <option value="image">Docker Image</option>
              <option value="fs">Filesystem</option>
              <option value="repo">Git Repository</option>
              <option value="config">Config File</option>
            </select>
          </div>
          
          <div class="form-group">
            <label>Target:</label>
            <input v-model="scanForm.target" placeholder="e.g., nginx:latest" required />
          </div>
          
          <div class="form-group">
            <label>Severity:</label>
            <div class="checkbox-group">
              <label><input type="checkbox" value="CRITICAL" v-model="scanForm.severity"> Critical</label>
              <label><input type="checkbox" value="HIGH" v-model="scanForm.severity"> High</label>
              <label><input type="checkbox" value="MEDIUM" v-model="scanForm.severity"> Medium</label>
              <label><input type="checkbox" value="LOW" v-model="scanForm.severity"> Low</label>
            </div>
          </div>
          
          <div class="form-group">
            <label><input type="checkbox" v-model="scanForm.ignoreUnfixed"> Ignore Unfixed</label>
            <label><input type="checkbox" v-model="scanForm.skipUpdate"> Skip DB Update</label>
          </div>
          
          <button type="submit" :disabled="loading">
            {{ loading ? 'Creating...' : 'Start Scan' }}
          </button>
        </form>
      </div>
      
      <div class="scans-list">
        <h2>Recent Scans</h2>
        <button @click="refreshScans">🔄 Refresh</button>
        
        <div v-if="scans.length === 0" class="empty">
          No scans yet. Create one above!
        </div>
        
        <div v-for="scan in scans" :key="scan.task_id" class="scan-item">
          <div class="scan-header">
            <span class="scan-type">{{ scan.type }}</span>
            <span :class="['scan-status', scan.status]">{{ scan.status }}</span>
          </div>
          <div class="scan-target">{{ scan.target }}</div>
          <div class="scan-time">{{ formatDate(scan.created_at) }}</div>
          <div class="scan-actions">
            <button @click="viewScan(scan.task_id)">View Details</button>
            <button v-if="scan.status === 'completed'" @click="downloadReport(scan.task_id)">
              📥 Download
            </button>
          </div>
        </div>
      </div>
      
      <div v-if="selectedScan" class="scan-details">
        <div class="modal-overlay" @click="selectedScan = null">
          <div class="modal-content" @click.stop>
            <button class="close-btn" @click="selectedScan = null">✕</button>
            <h2>Scan Details</h2>
            
            <div class="detail-group">
              <strong>Task ID:</strong> {{ selectedScan.task_id }}
            </div>
            <div class="detail-group">
              <strong>Type:</strong> {{ selectedScan.type }}
            </div>
            <div class="detail-group">
              <strong>Target:</strong> {{ selectedScan.target }}
            </div>
            <div class="detail-group">
              <strong>Status:</strong> 
              <span :class="['scan-status', selectedScan.status]">{{ selectedScan.status }}</span>
            </div>
            
            <div v-if="selectedScan.result" class="scan-results">
              <h3>Vulnerabilities Summary</h3>
              <div v-for="result in selectedScan.result.Results" :key="result.Target">
                <h4>{{ result.Target }}</h4>
                <div v-if="result.Vulnerabilities">
                  <p>Total: {{ result.Vulnerabilities.length }}</p>
                  <div class="vuln-list">
                    <div v-for="vuln in result.Vulnerabilities.slice(0, 10)" :key="vuln.VulnerabilityID" class="vuln-item">
                      <span :class="['severity-badge', vuln.Severity]">{{ vuln.Severity }}</span>
                      <strong>{{ vuln.VulnerabilityID }}</strong>
                      <span>{{ vuln.PkgName }}</span>
                    </div>
                  </div>
                </div>
                <div v-else>
                  <p>✅ No vulnerabilities found</p>
                </div>
              </div>
            </div>
            
            <div v-if="selectedScan.error" class="error-message">
              <strong>Error:</strong> {{ selectedScan.error }}
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>
</template>

<script>
import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default {
  data() {
    return {
      scanForm: {
        type: 'image',
        target: '',
        severity: ['CRITICAL', 'HIGH'],
        ignoreUnfixed: false,
        skipUpdate: false
      },
      scans: [],
      selectedScan: null,
      loading: false
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
        const payload = {
          type: this.scanForm.type,
          target: this.scanForm.target,
          options: {
            severity: this.scanForm.severity,
            ignore_unfixed: this.scanForm.ignoreUnfixed,
            skip_update: this.scanForm.skipUpdate
          }
        }
        
        await axios.post(`${API_URL}/api/scan`, payload)
        alert('Scan started successfully!')
        this.scanForm.target = ''
        this.refreshScans()
      } catch (error) {
        alert('Failed to create scan: ' + error.message)
      } finally {
        this.loading = false
      }
    },
    
    async refreshScans() {
      try {
        const response = await axios.get(`${API_URL}/api/scans`)
        this.scans = response.data.scans.sort((a, b) => 
          new Date(b.created_at) - new Date(a.created_at)
        )
      } catch (error) {
        console.error('Failed to fetch scans:', error)
      }
    },
    
    async viewScan(taskId) {
      try {
        const response = await axios.get(`${API_URL}/api/scan/${taskId}`)
        this.selectedScan = response.data
      } catch (error) {
        alert('Failed to fetch scan details: ' + error.message)
      }
    },
    
    async downloadReport(taskId) {
      window.open(`${API_URL}/api/scan/${taskId}/report`, '_blank')
    },
    
    formatDate(dateString) {
      return new Date(dateString).toLocaleString()
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
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  background: #f5f5f5;
}

#app {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

header {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 30px;
  border-radius: 10px;
  margin-bottom: 30px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

h1 {
  font-size: 2em;
}

main {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

.scan-form, .scans-list {
  background: white;
  padding: 25px;
  border-radius: 10px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.form-group {
  margin-bottom: 20px;
}

label {
  display: block;
  margin-bottom: 8px;
  font-weight: 600;
  color: #333;
}

input, select {
  width: 100%;
  padding: 10px;
  border: 2px solid #e0e0e0;
  border-radius: 5px;
  font-size: 14px;
}

input:focus, select:focus {
  outline: none;
  border-color: #667eea;
}

.checkbox-group {
  display: flex;
  gap: 15px;
  flex-wrap: wrap;
}

.checkbox-group label {
  display: flex;
  align-items: center;
  gap: 5px;
  font-weight: normal;
}

button {
  background: #667eea;
  color: white;
  border: none;
  padding: 12px 24px;
  border-radius: 5px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 600;
  transition: background 0.3s;
}

button:hover {
  background: #5568d3;
}

button:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.scan-item {
  background: #f9f9f9;
  padding: 15px;
  margin-bottom: 15px;
  border-radius: 8px;
  border-left: 4px solid #667eea;
}

.scan-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 10px;
}

.scan-type {
  background: #e0e7ff;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
  color: #667eea;
}

.scan-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
}

.scan-status.pending { background: #fef3c7; color: #92400e; }
.scan-status.running { background: #dbeafe; color: #1e40af; }
.scan-status.completed { background: #d1fae5; color: #065f46; }
.scan-status.failed { background: #fee2e2; color: #991b1b; }

.scan-target {
  font-weight: 600;
  color: #333;
  margin-bottom: 5px;
}

.scan-time {
  font-size: 12px;
  color: #666;
  margin-bottom: 10px;
}

.scan-actions {
  display: flex;
  gap: 10px;
}

.scan-actions button {
  padding: 6px 12px;
  font-size: 12px;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0,0,0,0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  padding: 30px;
  border-radius: 10px;
  max-width: 800px;
  max-height: 80vh;
  overflow-y: auto;
  position: relative;
}

.close-btn {
  position: absolute;
  top: 15px;
  right: 15px;
  background: #f5f5f5;
  color: #333;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  padding: 0;
}

.detail-group {
  margin-bottom: 15px;
}

.severity-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  margin-right: 8px;
}

.severity-badge.CRITICAL { background: #fee2e2; color: #991b1b; }
.severity-badge.HIGH { background: #fed7aa; color: #9a3412; }
.severity-badge.MEDIUM { background: #fef3c7; color: #92400e; }
.severity-badge.LOW { background: #e0e7ff; color: #3730a3; }

.vuln-list {
  max-height: 400px;
  overflow-y: auto;
}

.vuln-item {
  padding: 10px;
  background: #f9f9f9;
  margin-bottom: 8px;
  border-radius: 5px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.empty {
  text-align: center;
  color: #999;
  padding: 40px;
}

@media (max-width: 768px) {
  main {
    grid-template-columns: 1fr;
  }
}
</style>