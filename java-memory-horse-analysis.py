import os
import subprocess
import re
import logging
from typing import Dict, List, Optional
from datetime import datetime

class JavaProcessAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.setup_logging()

    def setup_logging(self):
        """设置日志配置"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=f'java_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        )

    def get_java_processes(self) -> Dict[str, str]:
        """获取运行中的Java进程列表"""
        try:
            result = subprocess.run(
                ['jps', '-v'], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=30
            )
            processes = {}
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) > 1:
                            pid = parts[0]
                            command = ' '.join(parts[1:])
                            processes[pid] = command
            return processes
        except subprocess.TimeoutExpired:
            self.logger.error("获取Java进程列表超时")
        except Exception as e:
            self.logger.error(f"获取Java进程失败: {str(e)}")
        return {}

    def analyze_web_components(self, pid: str) -> List[Dict]:
        """分析Web容器组件"""
        components = []
        try:
            cmd = f"jcmd {pid} VM.classloaders"
            result = subprocess.run(
                cmd.split(), 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                # 分析class loader信息
                loaders = self._parse_classloader_output(result.stdout)
                components.extend(loaders)
        except Exception as e:
            self.logger.error(f"分析Web组件失败: {str(e)}")
        return components

    def _parse_classloader_output(self, output: str) -> List[Dict]:
        """解析类加载器输出"""
        loaders = []
        current_loader = {}
        for line in output.split('\n'):
            if line.strip():
                if line.startswith('ClassLoader'):
                    if current_loader:
                        loaders.append(current_loader)
                    current_loader = {'type': line.strip()}
                elif current_loader:
                    # 添加类加载器详细信息
                    parts = line.strip().split(':')
                    if len(parts) == 2:
                        current_loader[parts[0].strip()] = parts[1].strip()
        if current_loader:
            loaders.append(current_loader)
        return loaders

    def analyze_threads(self, pid: str) -> List[Dict]:
        """分析线程信息"""
        threads = []
        try:
            cmd = f"jstack {pid}"
            result = subprocess.run(
                cmd.split(), 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                threads = self._parse_thread_dump(result.stdout)
        except Exception as e:
            self.logger.error(f"分析线程失败: {str(e)}")
        return threads

    def _parse_thread_dump(self, output: str) -> List[Dict]:
        """解析线程转储信息"""
        threads = []
        current_thread = {}
        for line in output.split('\n'):
            if line.startswith('"'):
                if current_thread:
                    threads.append(current_thread)
                current_thread = {
                    'name': line.split('"')[1],
                    'state': None,
                    'stack': []
                }
            elif 'java.lang.Thread.State:' in line and current_thread:
                current_thread['state'] = line.split(':')[1].strip()
            elif line.strip().startswith('at ') and current_thread:
                current_thread['stack'].append(line.strip())
        if current_thread:
            threads.append(current_thread)
        return threads

    def analyze_system_properties(self, pid: str) -> Dict:
        """分析JVM系统属性"""
        properties = {}
        try:
            cmd = f"jcmd {pid} VM.system_properties"
            result = subprocess.run(
                cmd.split(), 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        properties[key.strip()] = value.strip()
        except Exception as e:
            self.logger.error(f"分析系统属性失败: {str(e)}")
        return properties

    def analyze_jsp_files(self, directory: str) -> List[Dict]:
        """分析JSP文件"""
        results = []
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith('.jsp'):
                        file_path = os.path.join(root, file)
                        result = self._analyze_single_jsp(file_path)
                        if result:
                            results.append(result)
        except Exception as e:
            self.logger.error(f"分析JSP文件失败: {str(e)}")
        return results

    def _analyze_single_jsp(self, file_path: str) -> Optional[Dict]:
        """分析单个JSP文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return {
                    'path': file_path,
                    'size': os.path.getsize(file_path),
                    'last_modified': datetime.fromtimestamp(
                        os.path.getmtime(file_path)
                    ).isoformat(),
                    'scriptlets': len(re.findall(r'<%.*?%>', content, re.DOTALL))
                }
        except Exception as e:
            self.logger.error(f"分析文件 {file_path} 失败: {str(e)}")
        return None

    def generate_report(self, output_file: str = None):
        """生成分析报告"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'processes': {},
            'warnings': []
        }

        java_processes = self.get_java_processes()
        for pid, command in java_processes.items():
            process_info = {
                'command': command,
                'web_components': self.analyze_web_components(pid),
                'threads': self.analyze_threads(pid),
                'system_properties': self.analyze_system_properties(pid)
            }
            report['processes'][pid] = process_info

        if output_file:
            with open(output_file, 'w') as f:
                import json
                json.dump(report, f, indent=2)

        return report

def main():
    analyzer = JavaProcessAnalyzer()
    print("[*] 开始分析Java进程...")
    report = analyzer.generate_report("java_analysis_report.json")
    print(f"[+] 分析完成，报告已保存到 java_analysis_report.json")

if __name__ == "__main__":
    main()
