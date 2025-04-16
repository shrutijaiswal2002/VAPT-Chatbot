# app.py
from flask import Flask, render_template, request, jsonify
import requests
import json
import os
import time
from threading import Thread
import random
import re
import subprocess
import urllib.parse

app = Flask(__name__)

# This would be loaded from environment variables in production
API_KEYS = {
    "OPENAI_API_KEY": "your-openai-api-key-here",
    # Add any other API keys needed
}

# Global variable to store scan results
current_scan = {
    "status": "idle",
    "url": "",
    "progress": 0,
    "results": None
}

def is_valid_url(url):
    """Check if the URL is valid and safe to scan"""
    if not url.startswith(('http://', 'https://')):
        return False
    
    # Additional validation can be added here
    return True

def sanitize_url(url):
    """Sanitize the URL to prevent command injection"""
    # Basic sanitization
    return urllib.parse.quote(url)

def run_basic_scan(url):
    """Run basic HTTP checks on the website"""
    results = {}
    
    try:
        # Check HTTP response
        response = requests.get(url, timeout=10, allow_redirects=True)
        results["status_code"] = response.status_code
        
        # Check headers
        headers = dict(response.headers)
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not set"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Not set"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not set"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Not set"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "Not set"),
        }
        results["security_headers"] = security_headers
        
        # Check for cookies and their security
        cookies = response.cookies
        cookie_details = []
        for cookie in cookies:
            cookie_details.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.has_nonstandard_attr("SameSite")
            })
        results["cookies"] = cookie_details
        
        return results
    except Exception as e:
        return {"error": str(e)}

def run_port_scan(url):
    """Run a basic port scan on the host"""
    # Extract domain from URL
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    
    # Mock port scan results (in production, you'd use a real scanner like nmap)
    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
        21: "FTP"
    }
    
    results = {}
    for port, service in common_ports.items():
        # Simulate port scanning
        is_open = random.choice([True, False]) if port not in [80, 443] else True
        results[port] = {
            "service": service,
            "status": "open" if is_open else "closed"
        }
    
    return results

def analyze_with_ollama(data):
    """Send data to Ollama model for vulnerability analysis"""
    try:
        # This would be the actual Ollama API endpoint in production
        ollama_url = "http://localhost:11434/api/generate"
        
        prompt = f"""
        You are a cybersecurity expert performing vulnerability assessment.
        Analyze the following data from a website scan and identify potential security vulnerabilities
        according to OWASP Top 10 and other security best practices.
        
        Data:
        {json.dumps(data, indent=2)}
        
        Provide a detailed security analysis and recommendations.
        """
        
        # For demonstration, we'll simulate a response
        # In production, you would use:
        # response = requests.post(ollama_url, json={"model": "llama3", "prompt": prompt})
        
        time.sleep(2)  # Simulate API call delay
        
        analysis = {
            "vulnerabilities": [
                {
                    "type": "Missing Security Headers",
                    "description": "The site is missing important security headers like Content-Security-Policy.",
                    "severity": "Medium",
                    "recommendation": "Implement proper security headers to prevent XSS and other attacks."
                }
            ],
            "overall_assessment": "The website has several potential security issues that should be addressed."
        }
        
        if "security_headers" in data:
            # Check each security header
            if data["security_headers"]["Content-Security-Policy"] == "Not set":
                analysis["vulnerabilities"].append({
                    "type": "Missing CSP",
                    "description": "Content Security Policy header is not set, which could make the site vulnerable to XSS attacks.",
                    "severity": "High",
                    "recommendation": "Implement a strict Content Security Policy."
                })
            
            if data["security_headers"]["X-Frame-Options"] == "Not set":
                analysis["vulnerabilities"].append({
                    "type": "Clickjacking Vulnerability",
                    "description": "X-Frame-Options header is not set, making the site potentially vulnerable to clickjacking attacks.",
                    "severity": "Medium",
                    "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN."
                })
        
        return analysis
    except Exception as e:
        return {"error": str(e)}

def analyze_with_chatgpt(data):
    """Send data to ChatGPT API for vulnerability analysis"""
    try:
        # This would be the actual OpenAI API call in production
        # headers = {"Authorization": f"Bearer {API_KEYS['OPENAI_API_KEY']}"}
        
        prompt = f"""
        You are a cybersecurity expert specializing in web application security.
        Perform a thorough vulnerability assessment of the following scan data:
        
        {json.dumps(data, indent=2)}
        
        Provide a detailed report including:
        1. Identified vulnerabilities (with CVSS scores if applicable)
        2. Potential attack vectors
        3. Remediation recommendations
        4. Overall risk assessment
        
        Focus on OWASP Top 10 vulnerabilities and security best practices.
        """
        
        # Simulate API call delay
        time.sleep(3)
        
        # Mock response - in production, this would come from the actual API
        analysis = {
            "report_summary": "The scan identified several potential security issues of varying severity.",
            "vulnerabilities": [
                {
                    "name": "Insecure Cookie Configuration",
                    "cvss": 5.4,
                    "description": "Cookies are not using secure and HttpOnly flags, making them vulnerable to theft through XSS attacks.",
                    "remediation": "Set Secure and HttpOnly flags on all sensitive cookies."
                }
            ],
            "overall_risk": "Medium"
        }
        
        # Add simulated findings based on the input data
        if "cookies" in data:
            for cookie in data["cookies"]:
                if not cookie["secure"] or not cookie["httponly"]:
                    analysis["vulnerabilities"].append({
                        "name": f"Insecure Cookie: {cookie['name']}",
                        "cvss": 4.8,
                        "description": f"The {cookie['name']} cookie is not properly secured with HttpOnly and Secure flags.",
                        "remediation": "Update cookie settings to include HttpOnly and Secure flags."
                    })
        
        # Add port-related findings
        if "port_scan" in data:
            for port, info in data["port_scan"].items():
                if info["status"] == "open" and port not in [80, 443]:
                    analysis["vulnerabilities"].append({
                        "name": f"Exposed Service: {info['service']} on port {port}",
                        "cvss": 6.2,
                        "description": f"The {info['service']} service is exposed on port {port}, which may not be necessary for website operation.",
                        "remediation": f"Close port {port} if not required or restrict access with a firewall."
                    })
        
        return analysis
    except Exception as e:
        return {"error": str(e)}

def perform_scan(url):
    """Main function to perform the complete vulnerability scan"""
    global current_scan
    
    try:
        current_scan["status"] = "running"
        current_scan["url"] = url
        current_scan["progress"] = 0
        
        # Update progress
        current_scan["progress"] = 10
        time.sleep(1)  # Simulate work
        
        # Step 1: Basic HTTP checks
        basic_results = run_basic_scan(url)
        current_scan["progress"] = 30
        time.sleep(1)  # Simulate work
        
        # Step 2: Port scanning
        port_results = run_port_scan(url)
        current_scan["progress"] = 50
        time.sleep(1)  # Simulate work
        
        # Combine results so far
        combined_data = {
            "basic_scan": basic_results,
            "port_scan": port_results
        }
        
        # Step 3: Analysis with Ollama
        ollama_analysis = analyze_with_ollama(combined_data)
        current_scan["progress"] = 70
        time.sleep(1)  # Simulate work
        
        # Step 4: Analysis with ChatGPT
        chatgpt_analysis = analyze_with_chatgpt(combined_data)
        current_scan["progress"] = 90
        time.sleep(1)  # Simulate work
        
        # Combine all results
        final_results = {
            "scan_data": combined_data,
            "ollama_analysis": ollama_analysis,
            "chatgpt_analysis": chatgpt_analysis,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        current_scan["results"] = final_results
        current_scan["progress"] = 100
        current_scan["status"] = "completed"
        
        return final_results
    except Exception as e:
        current_scan["status"] = "error"
        current_scan["results"] = {"error": str(e)}
        return {"error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format"}), 400
    
    # Start scan in a background thread
    scan_thread = Thread(target=perform_scan, args=(url,))
    scan_thread.start()
    
    return jsonify({"status": "scan_started"})

@app.route('/api/scan/status', methods=['GET'])
def get_scan_status():
    return jsonify({
        "status": current_scan["status"],
        "progress": current_scan["progress"],
        "url": current_scan["url"]
    })

@app.route('/api/scan/results', methods=['GET'])
def get_scan_results():
    if current_scan["status"] != "completed":
        return jsonify({"error": "No completed scan results available"}), 404
    
    return jsonify(current_scan["results"])

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({"error": "Message is required"}), 400
    
    # Check if it's a URL submission for scanning
    if re.match(r'^https?://', message):
        return jsonify({
            "response": f"Would you like me to scan {message} for vulnerabilities? Please click the 'Scan' button to proceed."
        })
    
    # Process the chat message
    if current_scan["results"] is not None:
        # If we have scan results, we can provide more context-aware responses
        response = process_chat_with_context(message, current_scan["results"])
    else:
        # Generic responses without scan context
        response = process_chat_generic(message)
    
    return jsonify({"response": response})

def process_chat_with_context(message, context):
    """Process chat messages with context from scan results"""
    message_lower = message.lower()
    
    # Handle specific questions about the scan
    if "vulnerabilities" in message_lower or "issues" in message_lower:
        ollama_vulns = context.get("ollama_analysis", {}).get("vulnerabilities", [])
        chatgpt_vulns = context.get("chatgpt_analysis", {}).get("vulnerabilities", [])
        
        total_vulns = len(ollama_vulns) + len(chatgpt_vulns)
        if total_vulns > 0:
            response = f"I found {total_vulns} potential vulnerabilities in the scan. "
            
            # List a few examples
            if len(ollama_vulns) > 0:
                response += f"For example: {ollama_vulns[0].get('type', 'Unknown vulnerability')} - {ollama_vulns[0].get('description', 'No description')}. "
            
            response += "Would you like to see the full vulnerability report?"
        else:
            response = "No significant vulnerabilities were found in the scan. However, this doesn't guarantee the site is completely secure."
    
    elif "headers" in message_lower or "security headers" in message_lower:
        headers = context.get("scan_data", {}).get("basic_scan", {}).get("security_headers", {})
        if headers:
            missing_headers = [name for name, value in headers.items() if value == "Not set"]
            if missing_headers:
                response = f"The site is missing several important security headers: {', '.join(missing_headers)}. These headers help protect against common web vulnerabilities."
            else:
                response = "All important security headers appear to be properly set. This is good security practice!"
        else:
            response = "I couldn't find information about security headers in the scan results."
    
    elif "severity" in message_lower or "risk" in message_lower:
        overall_risk = context.get("chatgpt_analysis", {}).get("overall_risk", "Unknown")
        response = f"The overall risk level for this site was assessed as {overall_risk}. "
        
        # Add recommendation based on risk level
        if overall_risk.lower() == "high":
            response += "I recommend addressing these security issues as soon as possible."
        elif overall_risk.lower() == "medium":
            response += "You should plan to address these security concerns in your next development cycle."
        else:
            response += "While the risk is lower, following security best practices is always recommended."
    
    else:
        # Generic response incorporating scan information
        site_url = context.get("scan_data", {}).get("url", current_scan["url"])
        response = f"I've analyzed {site_url} for vulnerabilities. Ask me about specific security aspects like 'vulnerabilities', 'security headers', or 'overall risk'."
    
    return response

def process_chat_generic(message):
    """Process generic chat messages without scan context"""
    message_lower = message.lower()
    
    if "hello" in message_lower or "hi" in message_lower or "hey" in message_lower:
        return "Hello! I'm your VAPT (Vulnerability Assessment and Penetration Testing) assistant. I can help you scan websites for security vulnerabilities. Just provide a URL and click the Scan button."
    
    elif "how" in message_lower and "work" in message_lower:
        return "I analyze websites for security vulnerabilities by checking HTTP headers, cookies, open ports, and other security indicators. I then use AI models (Ollama and ChatGPT) to provide detailed analysis and recommendations."
    
    elif "owasp" in message_lower:
        return "OWASP (Open Web Application Security Project) maintains a list of the top 10 most critical web application security risks. These include injection flaws, broken authentication, sensitive data exposure, and more. I can help identify these vulnerabilities in websites."
    
    elif "vulnerability" in message_lower or "security" in message_lower:
        return "To check a website for vulnerabilities, please enter its URL and click the Scan button. I'll analyze it and provide a comprehensive security report."
    
    else:
        return "I'm your VAPT assistant. I can scan websites for security vulnerabilities and provide detailed reports. Enter a URL to begin scanning, or ask me about web security concepts."

if __name__ == '__main__':
    app.run(debug=True)