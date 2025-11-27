# backend/app.py
from flask import Flask, request, jsonify, send_file, make_response
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

def generate_html_report(task_id):
    """生成 HTML 格式报告"""
    if task_id not in scan_tasks:
        return None
    
    task = scan_tasks[task_id]
    if task['status'] != 'completed' or 'result' not in task:
        return None
    
    result = task['result']
    stats = task.get('stats', {})
    
    html_template = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描报告 - {{ target }}</title>
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
            padding: 28px 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
            overflow: hidden;
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
        
        .hdr-text {
            display: flex;
            flex-direction: column;
        }
        
        .hdr-text > div:first-child {
            font-weight: 700;
            font-size: 18px;
        }
        
        .hdr-text > div:last-child {
            font-size: 13px;
            color: #eaf6ff;
            margin-top: 2px;
        }
        
        .report-info {
            padding: 22px;
            background: #fafafa;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 12px;
        }
        
        .info-item {
            font-size: 14px;
            color: #374151;
        }
        
        .info-item strong {
            color: #111827;
            margin-right: 8px;
        }
        
        .summary {
            padding: 22px;
            background: white;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .summary h2 {
            font-size: 16px;
            margin-bottom: 16px;
            color: #111827;
            font-weight: 600;
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
        
        .details {
            padding: 22px;
        }
        
        .section {
            margin-bottom: 32px;
        }
        
        .section h3 {
            font-size: 16px;
            margin-bottom: 12px;
            color: #111827;
            font-weight: 600;
        }
        
        .target-info {
            background: #f9fafb;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 16px;
            font-size: 14px;
        }
        
        .vuln-table {
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            overflow: hidden;
            margin-top: 12px;
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
        
        .no-vuln-message {
            padding: 20px;
            text-align: center;
            background: #f0fdf4;
            color: #059669;
            border-radius: 6px;
            font-weight: 500;
        }
        
        .footer {
            padding: 14px;
            background: #fafafa;
            color: #6b7280;
            font-size: 13px;
            text-align: center;
            border-top: 1px solid #e5e7eb;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
            }
        }
        
        @media (max-width: 768px) {
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
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="hdr">
            <div class="logo">🛡️</div>
            <div class="hdr-text">
                <div>安全漏洞扫描系统</div>
                <div>Security Vulnerability Scanner</div>
            </div>
        </div>
        
        <div class="report-info">
            <div class="info-grid">
                <div class="info-item"><strong>扫描目标:</strong>{{ target }}</div>
                <div class="info-item"><strong>扫描类型:</strong>{{ scan_type }}</div>
                <div class="info-item"><strong>生成时间:</strong>{{ report_time }}</div>
            </div>
        </div>
        
        <div class="summary">
            <h2>漏洞统计摘要</h2>
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="stat-number">{{ stats.critical }}</div>
                    <div class="stat-text">严重漏洞</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{{ stats.high }}</div>
                    <div class="stat-text">高危漏洞</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{{ stats.medium }}</div>
                    <div class="stat-text">中危漏洞</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">{{ stats.low }}</div>
                    <div class="stat-text">低危漏洞</div>
                </div>
            </div>
        </div>
        
        <div class="details">
            {% for result in results %}
            <div class="section">
                <h3>{{ result.Target }}</h3>
                
                <div class="target-info">
                    <strong>类型:</strong> {{ result.Type }}
                    {% if result.Class %}
                    | <strong>分类:</strong> {{ result.Class }}
                    {% endif %}
                </div>
                
                {% if result.Vulnerabilities %}
                <div class="vuln-table">
                    <div class="vuln-row vuln-header">
                        <div class="vuln-cell">漏洞编号</div>
                        <div class="vuln-cell">严重程度</div>
                        <div class="vuln-cell">包名</div>
                        <div class="vuln-cell">版本</div>
                    </div>
                    {% for vuln in result.Vulnerabilities %}
                    <div class="vuln-row">
                        <div class="vuln-cell">{{ vuln.VulnerabilityID }}</div>
                        <div class="vuln-cell">
                            <span class="severity-badge {{ vuln.Severity|lower }}">
                                {% if vuln.Severity == 'CRITICAL' %}严重
                                {% elif vuln.Severity == 'HIGH' %}高危
                                {% elif vuln.Severity == 'MEDIUM' %}中危
                                {% elif vuln.Severity == 'LOW' %}低危
                                {% else %}{{ vuln.Severity }}
                                {% endif %}
                            </span>
                        </div>
                        <div class="vuln-cell">{{ vuln.PkgName }}</div>
                        <div class="vuln-cell">{{ vuln.InstalledVersion }}</div>
                    </div>
                    {% endfor %}
                </div>
                {% else %}
                <div class="no-vuln-message">
                    ✓ 未发现漏洞
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            本报告由安全漏洞扫描系统自动生成 | Powered by Trivy
        </div>
    </div>
</body>
</html>
    '''
    
    from jinja2 import Template
    template = Template(html_template)
    
    scan_type_map = {'image': 'Docker 镜像', 'repo': 'GitHub 仓库'}
    
    html = template.render(
        target=task['target'],
        scan_type=scan_type_map.get(task['type'], task['type']),
        report_time=datetime.now().strftime('%Y年%m月%d日 %H:%M:%S'),
        stats=stats,
        results=result.get('Results', [])
    )
    
    return html

def generate_pdf_report(task_id):
    """生成 PDF 格式报告"""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.units import inch
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        if task_id not in scan_tasks:
            return None
        
        task = scan_tasks[task_id]
        if task['status'] != 'completed' or 'result' not in task:
            return None
        
        result = task['result']
        stats = task.get('stats', {})
        
        pdf_path = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.pdf")
        doc = SimpleDocTemplate(
            pdf_path, 
            pagesize=A4, 
            topMargin=0.5*inch, 
            bottomMargin=0.5*inch,
            leftMargin=0.75*inch,
            rightMargin=0.75*inch
        )
        story = []
        
        styles = getSampleStyleSheet()
        
        # 自定义样式 - 使用 Helvetica（内置，支持良好）
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=32,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=20,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=20,
            textColor=colors.HexColor('#111827'),
            spaceAfter=10,
            spaceBefore=10
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14
        )
        
        # 标题（使用英文避免字体问题）
        story.append(Paragraph("Security Vulnerability Scan Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # 基本信息
        scan_type_text = "Docker Image" if task['type'] == 'image' else "GitHub Repository"
        info_data = [
            ['Scan Target', task['target']],
            ['Scan Type', scan_type_text],
            ['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]
        info_table = Table(info_data, colWidths=[2*inch, 4.5*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9fafb')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('LEADING', (0, 0), (-1, -1), 14),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.4*inch))
        
        # 统计摘要
        story.append(Paragraph("Vulnerability Summary", heading_style))
        story.append(Spacer(1, 0.15*inch))
        
        stats_data = [
            ['Critical\nCRITICAL', 'High\nHIGH', 'Medium\nMEDIUM', 'Low\nLOW'],
            [str(stats['critical']), str(stats['high']), str(stats['medium']), str(stats['low'])]
        ]
        stats_table = Table(stats_data, colWidths=[1.625*inch]*4)
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('LEADING', (0, 0), (-1, 0), 14),
            ('FONTSIZE', (0, 1), (-1, -1), 20),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica-Bold'),
            ('LEADING', (0, 1), (-1, -1), 24),
            ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#fee2e2')),
            ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#991b1b')),
            ('BACKGROUND', (1, 1), (1, 1), colors.HexColor('#fed7aa')),
            ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#9a3412')),
            ('BACKGROUND', (2, 1), (2, 1), colors.HexColor('#fef3c7')),
            ('TEXTCOLOR', (2, 1), (2, 1), colors.HexColor('#92400e')),
            ('BACKGROUND', (3, 1), (3, 1), colors.HexColor('#dbeafe')),
            ('TEXTCOLOR', (3, 1), (3, 1), colors.HexColor('#1e40af')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 0.4*inch))
        
        # 漏洞详情
        for idx, res in enumerate(result.get('Results', [])):
            story.append(Paragraph(f"Target {idx+1}: {res['Target']}", heading_style))
            story.append(Spacer(1, 0.1*inch))
            
            if res.get('Vulnerabilities'):
                total_vulns = len(res['Vulnerabilities'])
                story.append(Paragraph(f"Found {total_vulns} vulnerabilities", normal_style))
                story.append(Spacer(1, 0.1*inch))
                
                vuln_data = [['CVE ID', 'Severity', 'Package', 'Version', 'Fixed']]
                
                severity_map = {
                    'CRITICAL': 'CRITICAL',
                    'HIGH': 'HIGH',
                    'MEDIUM': 'MEDIUM',
                    'LOW': 'LOW'
                }
                
                for vuln in res['Vulnerabilities'][:40]:
                    vuln_data.append([
                        vuln['VulnerabilityID'][:20],
                        severity_map.get(vuln['Severity'], vuln['Severity']),
                        vuln['PkgName'][:24],
                        vuln.get('InstalledVersion', 'N/A')[:14],
                        vuln.get('FixedVersion', 'None')[:14]
                    ])
                
                vuln_table = Table(vuln_data, colWidths=[1.3*inch, 0.8*inch, 1.5*inch, 1.1*inch, 1.1*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('LEADING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 7),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fafafa')]),
                ]))
                story.append(vuln_table)
                
                if total_vulns > 40:
                    story.append(Spacer(1, 0.1*inch))
                    remaining = total_vulns - 40
                    story.append(Paragraph(f"Note: {remaining} more vulnerabilities not shown here", normal_style))
            else:
                story.append(Paragraph("No vulnerabilities found", normal_style))
            
            story.append(Spacer(1, 0.3*inch))
        
        # 页脚
        story.append(Spacer(1, 0.3*inch))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#6b7280'),
            alignment=TA_CENTER
        )
        story.append(Paragraph(
            f"Generated by Security Vulnerability Scanner | Powered by Trivy | {datetime.now().strftime('%Y-%m-%d')}", 
            footer_style
        ))
        
        # 生成 PDF
        doc.build(story)
        print(f"[{task_id}] PDF 报告已生成: {pdf_path}")
        return pdf_path
        
    except Exception as e:
        print(f"[{task_id}] 生成 PDF 失败: {e}")
        traceback.print_exc()
        return None

def run_trivy_scan(task_id, scan_type, target, options):
    """执行 Trivy 扫描"""
    output_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.json")
    
    try:
        scan_tasks[task_id]['status'] = 'running'
        scan_tasks[task_id]['started_at'] = datetime.now().isoformat()
        
        if scan_type == 'image':
            cmd = ['trivy', 'image', '--format', 'json', '--output', output_file, target]
        else:
            cmd = ['trivy', 'repo', '--format', 'json', '--output', output_file, target]
        
        cmd.extend(['--severity', 'CRITICAL,HIGH,MEDIUM,LOW'])
        cmd.extend(['--timeout', '10m'])
        
        print(f"[{task_id}] 执行命令: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=600,
            cwd='/tmp'
        )
        
        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            raise Exception(f"扫描未生成有效输出文件。错误: {result.stderr}")
        
        with open(output_file, 'r') as f:
            scan_result = json.load(f)
        
        stats = parse_vulnerabilities(scan_result)
        
        scan_tasks[task_id]['status'] = 'completed'
        scan_tasks[task_id]['result'] = scan_result
        scan_tasks[task_id]['stats'] = stats
        scan_tasks[task_id]['completed_at'] = datetime.now().isoformat()
        
        # 生成 HTML 报告
        html_path = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.html")
        html_content = generate_html_report(task_id)
        if html_content:
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[{task_id}] HTML 报告已生成")
        
        # 后台生成 PDF（不阻塞）
        def generate_pdf_async():
            try:
                generate_pdf_report(task_id)
            except Exception as e:
                print(f"[{task_id}] PDF 生成异步失败: {e}")
        
        pdf_thread = threading.Thread(target=generate_pdf_async)
        pdf_thread.daemon = True
        pdf_thread.start()
        
        print(f"[{task_id}] 扫描成功完成，发现 {stats['total']} 个漏洞")
        
    except Exception as e:
        error_msg = f'扫描失败: {str(e)}'
        print(f"[{task_id}] {error_msg}")
        scan_tasks[task_id]['status'] = 'failed'
        scan_tasks[task_id]['error'] = error_msg
        scan_tasks[task_id]['completed_at'] = datetime.now().isoformat()

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    try:
        result = subprocess.run(['trivy', 'version'], capture_output=True, text=True, timeout=5)
        trivy_version = result.stdout.strip().split('\n')[0] if result.returncode == 0 else 'unknown'
    except:
        trivy_version = 'unavailable'
    
    # 检查 wkhtmltopdf
    pdf_available = False
    try:
        result = subprocess.run(['wkhtmltopdf', '--version'], capture_output=True, timeout=5)
        pdf_available = result.returncode == 0
    except:
        pass
    
    return jsonify({
        'status': 'healthy',
        'service': 'trivy-scanner',
        'trivy_version': trivy_version,
        'pdf_support': pdf_available,
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
    
    if scan_type not in ['image', 'repo']:
        return jsonify({'error': '扫描类型必须是 image 或 repo'}), 400
    
    task_id = str(uuid.uuid4())
    
    scan_tasks[task_id] = {
        'id': task_id,
        'type': scan_type,
        'target': target,
        'status': 'pending',
        'created_at': datetime.now().isoformat()
    }
    
    thread = threading.Thread(target=run_trivy_scan, args=(task_id, scan_type, target, {}))
    thread.daemon = True
    thread.start()
    
    return jsonify({'task_id': task_id, 'status': 'pending'}), 202

@app.route('/api/scan/<task_id>', methods=['GET'])
def get_scan_status(task_id):
    """获取扫描状态"""
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

@app.route('/api/scan/<task_id>/report/json', methods=['GET'])
def download_json_report(task_id):
    """下载 JSON 报告"""
    if task_id not in scan_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    if scan_tasks[task_id]['status'] != 'completed':
        return jsonify({'error': '扫描尚未完成'}), 400
    
    report_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.json")
    if not os.path.exists(report_file):
        return jsonify({'error': '报告文件不存在'}), 404
    
    return send_file(report_file, as_attachment=True, download_name=f"scan-report-{task_id}.json")

@app.route('/api/scan/<task_id>/report/html', methods=['GET'])
def view_html_report(task_id):
    """查看 HTML 报告"""
    if task_id not in scan_tasks:
        return "任务不存在", 404
    
    if scan_tasks[task_id]['status'] != 'completed':
        return "扫描尚未完成", 400
    
    html_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.html")
    
    if not os.path.exists(html_file):
        html_content = generate_html_report(task_id)
        if not html_content:
            return "无法生成报告", 500
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    with open(html_file, 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/api/scan/<task_id>/report/pdf', methods=['GET'])
def download_pdf_report(task_id):
    """下载 PDF 报告"""
    if task_id not in scan_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    if scan_tasks[task_id]['status'] != 'completed':
        return jsonify({'error': '扫描尚未完成'}), 400
    
    pdf_file = os.path.join(SCAN_RESULTS_DIR, f"{task_id}.pdf")
    
    if not os.path.exists(pdf_file):
        pdf_path = generate_pdf_report(task_id)
        if not pdf_path:
            return jsonify({'error': 'PDF 生成失败'}), 500
    
    return send_file(pdf_file, as_attachment=True, download_name=f"scan-report-{task_id}.pdf")

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """列出所有扫描"""
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
    
    scans.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({'scans': scans})

if __name__ == '__main__':
    os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
    print(f"扫描结果目录: {SCAN_RESULTS_DIR}")
    app.run(host='0.0.0.0', port=8000, debug=False)