from flask import Flask, render_template, request, jsonify, Response
import requests
import ssl
import urllib3
from urllib3.util import ssl_
from requests.adapters import HTTPAdapter
import logging
import re
import urllib.parse
import os
import sys
from flask import Flask

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'))

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl_.create_urllib3_context(
            ssl_version=ssl.PROTOCOL_TLS,
            ciphers='DEFAULT@SECLEVEL=1'
        )
        # 添加旧服务器连接选项
        context.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
        # 禁用主机名检查
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = context
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)

def create_session():
    """创建一个配置好的会话对象"""
    session = requests.Session()
    adapter = TLSAdapter()
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    session.verify = False
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Referer': 'https://www.google.com/'
    })
    return session

def extract_redirect_url_from_html(html_content):
    """尝试从HTML内容中提取重定向URL"""
    # 尝试匹配meta刷新重定向
    meta_refresh = re.search(r'<meta[^>]*?url=([^"\'>]+)', html_content, re.IGNORECASE)
    if meta_refresh:
        return meta_refresh.group(1)
    
    # 尝试匹配JavaScript重定向
    js_redirect = re.search(r'window\.location\.(?:href|replace)\s*=\s*[\'"](https?://[^\'\"]+)[\'"]', html_content, re.IGNORECASE)
    if js_redirect:
        return js_redirect.group(1)
    
    # 尝试匹配任何URL
    any_url = re.search(r'https?://[^\s\'\"<>]+', html_content)
    if any_url:
        return any_url.group(0)
    
    return None

def decode_url_params(url):
    """解码URL中的参数，使其更易读"""
    try:
        # 解析URL
        parsed = urllib.parse.urlparse(url)
        
        # 解析查询参数
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # 检查是否有嵌套的URL参数
        for key, values in query_params.items():
            if any(v.startswith('http') for v in values):
                # 找到可能是嵌套URL的参数
                for i, value in enumerate(values):
                    if value.startswith('http'):
                        # 解码嵌套URL
                        values[i] = urllib.parse.unquote(value)
                query_params[key] = values
        
        # 重建查询字符串
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        
        # 重建URL
        decoded_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return decoded_url
    except Exception as e:
        logger.warning(f"URL解码失败: {str(e)}")
        return url  # 如果解码失败，返回原始URL

def expand_url(url):
    logger.info(f"尝试解析URL: {url}")
    original_url = url
    
    # 确保URL有协议前缀
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # 创建自定义会话
        session = create_session()
        
        # 尝试HEAD请求
        logger.info(f"尝试HEAD请求: {url}")
        response = session.head(url, allow_redirects=True, timeout=10)
        final_url = response.url
        
        # 检查是否真的重定向了
        if final_url == url or final_url == original_url:
            logger.warning(f"HEAD请求没有重定向，尝试GET请求")
            raise requests.RequestException("HEAD请求未重定向")
        
        logger.info(f"HEAD请求成功，最终URL: {final_url}")
        return decode_url_params(final_url), None
    except requests.RequestException as e1:
        logger.warning(f"HEAD请求失败或未重定向: {str(e1)}")
        try:
            # 如果HEAD失败，尝试GET请求
            logger.info(f"尝试GET请求: {url}")
            session = create_session()
            response = session.get(url, allow_redirects=True, timeout=15)
            final_url = response.url
            
            # 检查是否真的重定向了
            if final_url == url or final_url == original_url:
                logger.warning(f"GET请求没有重定向，尝试从HTML内容提取URL")
                # 尝试从HTML内容中提取URL
                html_content = response.text
                extracted_url = extract_redirect_url_from_html(html_content)
                if extracted_url:
                    logger.info(f"从HTML中提取到URL: {extracted_url}")
                    return decode_url_params(extracted_url), None
                else:
                    return None, "无法从响应中提取重定向URL"
            
            logger.info(f"GET请求成功，最终URL: {final_url}")
            return decode_url_params(final_url), None
        except requests.RequestException as e2:
            # 记录详细错误信息
            error_msg = f"HEAD错误: {str(e1)}, GET错误: {str(e2)}"
            logger.error(error_msg)
            return None, error_msg

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/expand', methods=['POST'])
def api_expand():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': '未提供 URL'}), 400
            
        long_url, error = expand_url(url)
        if error:
            logger.error(f"解析失败: {error}")
            return jsonify({'error': error}), 500
        
        # 确保返回的不是原始URL
        if long_url == url or (url.startswith('http') and long_url == url) or (not url.startswith('http') and long_url == f"https://{url}"):
            return jsonify({'error': '无法解析此短链接，服务器未返回重定向'}), 400
            
        return jsonify({'long_url': long_url})
    except Exception as e:
        logger.exception("API处理异常")
        return jsonify({'error': f"服务器内部错误: {str(e)}"}), 500

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 本地开发时使用
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
    
# Vercel Serverless Function 处理函数
def handler(event, context):
    return app
