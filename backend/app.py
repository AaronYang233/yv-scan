# backend/app.py (修复版)
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import subprocess
import json
import os
import uuid
from datetime import datetime
import threading
import traceback

app = Flask(__name__)
CORS(app)

SCAN_RESULTS_DIR = "/app/scan_results"
scan_tasks = {}

def parse_vulnerabilities(result):
    """解析漏洞统计"""
    stats = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'total': 0
    }
    
    if not result or 'Results' not in result:
        return stats
    
    for res in result.get('Results', []):
        if 'Vulnerabilities' in res and res['Vulnerabilities']:
            for vuln in res['Vulnerabilities']:
                severity = vuln.get('Severity', '').upper()
                if severity == 'CRITICAL':
                    stats['critical'] += 1
                elif severity == 'HIGH':
                    stats['high'] += 1
                elif severity == 'MEDIUM':
                    stats['medium'] += 1
                elif severity == 'LOW':
                    stats['low'] += 1
                stats['total'] += 1
    
    return stats

def run_trivy_scan(task_id, scan_type, target, options):
    """执行 Trivy 扫描"""
    output_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.json")
    
    try:
        scan_tasks[task_id]['status'] = 'running'
        scan_tasks[task_id]['started_at'] = datetime.now().isoformat()
        
        # 构建 Trivy 命令
        if scan_type == 'image':
            cmd = ['trivy', 'image', '--format', 'json', '--output', output_file, target]
        else:  # repo
            cmd = ['trivy', 'repo', '--format', 'json', '--output', output_file, target]
        
        # 添加严重等级过滤
        cmd.extend(['--severity', 'CRITICAL,HIGH,MEDIUM,LOW'])
        
        # 添加超时和其他选项
        cmd.extend(['--timeout', '10m'])
        
        print(f"[{task_id}] 执行命令: {' '.join(cmd)}")
        
        # 执行扫描
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=600,
            cwd='/tmp'
        )
        
        print(f"[{task_id}] 返回码: {result.returncode}")
        print(f"[{task_id}] STDOUT: {result.stdout[:500]}")
        print(f"[{task_id}] STDERR: {result.stderr[:500]}")
        
        # 检查输出文件是否存在
        if not os.path.exists(output_file):
            raise Exception(f"扫描未生成输出文件。错误信息: {result.stderr}")
        
        # 检查文件大小
        file_size = os.path.getsize(output_file)
        print(f"[{task_id}] 输出文件大小: {file_size} bytes")
        
        if file_size == 0:
            raise Exception(f"扫描输出文件为空。错误信息: {result.stderr}")
        
        # 读取并验证结果
        with open(output_file, 'r') as f:
            scan_result = json.load(f)
        
        # 解析统计信息
        stats = parse_vulnerabilities(scan_result)
        
        scan_tasks[task_id]['status'] = 'completed'
        scan_tasks[task_id]['result'] = scan_result
        scan_tasks[task_id]['stats'] = stats
        scan_tasks[task_id]['completed_at'] = datetime.now().isoformat()
        
        print(f"[{task_id}] 扫描成功完成，发现 {stats['total']} 个漏洞")
        
    except subprocess.TimeoutExpired:
        error_msg = '扫描超时（超过10分钟）'
        print(f"[{task_id}] {error_msg}")
        scan_tasks[task_id]['status'] = 'timeout'
        scan_tasks[task_id]['error'] = error_msg
        scan_tasks[task_id]['completed_at'] = datetime.now().isoformat()
        
    except json.JSONDecodeError as e:
        error_msg = f'扫描结果解析失败: {str(e)}'
        print(f"[{task_id}] {error_msg}")
        
        # 尝试读取文件内容
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                content = f.read()
                print(f"[{task_id}] 文件内容: {content[:500]}")
        
        scan_tasks[task_id]['status'] = 'failed'
        scan_tasks[task_id]['error'] = error_msg
        scan_tasks[task_id]['completed_at'] = datetime.now().isoformat()
        
    except Exception as e:
        error_msg = f'扫描失败: {str(e)}'
        print(f"[{task_id}] {error_msg}")
        print(f"[{task_id}] 详细错误:\n{traceback.format_exc()}")
        
        scan_tasks[task_id]['status'] = 'failed'
        scan_tasks[task_id]['error'] = error_msg
        scan_tasks[task_id]['completed_at'] = datetime.now().isoformat()

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    try:
        # 检查 Trivy 是否可用
        result = subprocess.run(
            ['trivy', 'version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        trivy_version = result.stdout.strip().split('\n')[0] if result.returncode == 0 else 'unknown'
    except:
        trivy_version = 'unavailable'
    
    return jsonify({
        'status': 'healthy',
        'service': 'trivy-scanner',
        'trivy_version': trivy_version,
        'scan_results_dir': SCAN_RESULTS_DIR,
        'tasks_count': len(scan_tasks)
    })

@app.route('/api/scan', methods=['POST'])
def create_scan():
    """创建扫描任务"""
    data = request.json
    
    scan_type = data.get('type')
    target = data.get('target')
    
    if not target or not scan_type:
        return jsonify({'error': '目标和类型不能为空'}), 400
    
    # 验证输入格式
    if scan_type not in ['image', 'repo']:
        return jsonify({'error': '扫描类型必须是 image 或 repo'}), 400
    
    if scan_type == 'repo':
        if not (target.startswith('http://') or target.startswith('https://')):
            return jsonify({'error': 'GitHub 仓库地址必须以 http:// 或 https:// 开头'}), 400
    
    task_id = str(uuid.uuid4())
    
    scan_tasks[task_id] = {
        'id': task_id,
        'type': scan_type,
        'target': target,
        'status': 'pending',
        'created_at': datetime.now().isoformat()
    }
    
    print(f"创建扫描任务: {task_id}, 类型: {scan_type}, 目标: {target}")
    
    thread = threading.Thread(
        target=run_trivy_scan,
        args=(task_id, scan_type, target, {})
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'task_id': task_id,
        'status': 'pending'
    }), 202

@app.route('/api/scan/<task_id>', methods=['GET'])
def get_scan_status(task_id):
    """获取扫描状态和结果"""
    if task_id not in scan_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
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
    if 'stats' in task:
        response['stats'] = task['stats']
    if task['status'] == 'completed' and 'result' in task:
        response['result'] = task['result']
    
    return jsonify(response)

@app.route('/api/scan/<task_id>/report', methods=['GET'])
def download_report(task_id):
    """下载扫描报告"""
    if task_id not in scan_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    if scan_tasks[task_id]['status'] != 'completed':
        return jsonify({'error': '扫描尚未完成'}), 400
    
    report_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.json")
    if not os.path.exists(report_file):
        return jsonify({'error': '报告文件不存在'}), 404
    
    return send_file(
        report_file, 
        as_attachment=True, 
        download_name=f"scan-report-{task_id}.json",
        mimetype='application/json'
    )

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """列出所有扫描任务"""
    scans = []
    for task_id, task in scan_tasks.items():
        scan_info = {
            'task_id': task['id'],
            'type': task['type'],
            'target': task['target'],
            'status': task['status'],
            'created_at': task['created_at']
        }
        if 'stats' in task:
            scan_info['stats'] = task['stats']
        if 'error' in task:
            scan_info['error'] = task['error']
        scans.append(scan_info)
    
    # 按创建时间倒序排列
    scans.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({'scans': scans})

@app.route('/api/debug/<task_id>', methods=['GET'])
def debug_task(task_id):
    """调试接口 - 查看任务详细信息"""
    if task_id not in scan_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = scan_tasks[task_id]
    output_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.json")
    
    debug_info = {
        'task': task,
        'output_file': output_file,
        'file_exists': os.path.exists(output_file),
        'file_size': os.path.getsize(output_file) if os.path.exists(output_file) else 0,
        'dir_contents': os.listdir(SCAN_RESULTS_DIR)
    }
    
    return jsonify(debug_info)

if __name__ == '__main__':
    # 确保扫描结果目录存在
    os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
    print(f"扫描结果目录: {SCAN_RESULTS_DIR}")
    print(f"启动 Flask 服务器...")
    app.run(host='0.0.0.0', port=8000, debug=False)