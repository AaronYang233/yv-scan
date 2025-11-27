# backend/app.py
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import subprocess
import json
import os
import uuid
from datetime import datetime
import threading

app = Flask(__name__)
CORS(app)

SCAN_RESULTS_DIR = "/app/scan_results"
scan_tasks = {}

def run_trivy_scan(task_id, scan_type, target, options):
    """执行 Trivy 扫描"""
    try:
        scan_tasks[task_id]['status'] = 'running'
        scan_tasks[task_id]['started_at'] = datetime.now().isoformat()
        
        output_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.json")
        
        # 构建 Trivy 命令
        cmd = ['trivy', scan_type, target, '--format', 'json', '--output', output_file]
        
        # 添加额外选项
        if options.get('severity'):
            cmd.extend(['--severity', ','.join(options['severity'])])
        if options.get('skip_update'):
            cmd.append('--skip-update')
        if options.get('ignore_unfixed'):
            cmd.append('--ignore-unfixed')
        
        # 执行扫描
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # 读取结果
        with open(output_file, 'r') as f:
            scan_result = json.load(f)
        
        scan_tasks[task_id]['status'] = 'completed'
        scan_tasks[task_id]['result'] = scan_result
        scan_tasks[task_id]['completed_at'] = datetime.now().isoformat()
        
    except subprocess.TimeoutExpired:
        scan_tasks[task_id]['status'] = 'timeout'
        scan_tasks[task_id]['error'] = 'Scan timeout after 10 minutes'
    except Exception as e:
        scan_tasks[task_id]['status'] = 'failed'
        scan_tasks[task_id]['error'] = str(e)
        scan_tasks[task_id]['completed_at'] = datetime.now().isoformat()

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({'status': 'healthy', 'service': 'trivy-scanner'})

@app.route('/api/scan', methods=['POST'])
def create_scan():
    """创建扫描任务"""
    data = request.json
    
    scan_type = data.get('type', 'image')  # image, fs, repo, config
    target = data.get('target')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # 生成任务 ID
    task_id = str(uuid.uuid4())
    
    # 初始化任务状态
    scan_tasks[task_id] = {
        'id': task_id,
        'type': scan_type,
        'target': target,
        'status': 'pending',
        'created_at': datetime.now().isoformat()
    }
    
    # 在后台线程中执行扫描
    thread = threading.Thread(
        target=run_trivy_scan,
        args=(task_id, scan_type, target, options)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'task_id': task_id,
        'status': 'pending'
    }), 202

@app.route('/api/scan/<task_id>', methods=['GET'])
def get_scan_status(task_id):
    """获取扫描状态"""
    if task_id not in scan_tasks:
        return jsonify({'error': 'Task not found'}), 404
    
    task = scan_tasks[task_id]
    response = {
        'task_id': task['id'],
        'type': task['type'],
        'target': task['target'],
        'status': task['status'],
        'created_at': task['created_at']
    }
    
    if 'started_at' in task:
        response['started_at'] = task['started_at']
    if 'completed_at' in task:
        response['completed_at'] = task['completed_at']
    if 'error' in task:
        response['error'] = task['error']
    if task['status'] == 'completed':
        response['result'] = task['result']
    
    return jsonify(response)

@app.route('/api/scan/<task_id>/report', methods=['GET'])
def download_report(task_id):
    """下载扫描报告"""
    if task_id not in scan_tasks:
        return jsonify({'error': 'Task not found'}), 404
    
    report_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.json")
    if not os.path.exists(report_file):
        return jsonify({'error': 'Report not found'}), 404
    
    return send_file(report_file, as_attachment=True)

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """列出所有扫描任务"""
    scans = []
    for task_id, task in scan_tasks.items():
        scans.append({
            'task_id': task['id'],
            'type': task['type'],
            'target': task['target'],
            'status': task['status'],
            'created_at': task['created_at']
        })
    return jsonify({'scans': scans})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)