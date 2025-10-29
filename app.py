import sys
import time
sys.path.append("/")

from flask import Flask, jsonify, request, make_response, render_template
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from protobuf import my_pb2, output_pb2

import os
import warnings
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

app = Flask(__name__)

def get_token(password, uid):
    """
    Obtain an OAuth token by posting the provided uid and password to the token endpoint.
    """
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return None
    return response.json()

def encrypt_message(key, iv, plaintext):
    """
    Encrypt a plaintext message using AES in CBC mode with PKCS#7 padding.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response(response_content):
    """
    Parse a string response that uses key: value pairs separated by newlines.
    """
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_token(uid, password):
    """
    Get token data and use it to build, serialize, encrypt, and send game data via protocol buffers.
    OB51 compatible version with new fields.
    """
    start_time = time.time() 

    token_data = get_token(password, uid)
    if not token_data:
        return {"error": "Failed to retrieve token"}

    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data.get('open_id', '')
    game_data.access_token = token_data.get('access_token', '')
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    
    # OB51 New Fields
    game_data.unknown_field_30 = 0
    game_data.secondary_network_provider = "Verizon Wireless"
    game_data.secondary_connection_type = "WIFI"
    game_data.unique_id = "74b585a9-0268-4ad3-8f36-ef41d2e53610"
    
    # Legacy Fields
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-GA': "v1 1",
        'X-Unity-Version': "2018.4.11f1",
        'ReleaseVersion': "OB51"
    }
    edata = bytes.fromhex(hex_encrypted_data)

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        elapsed_time = round(time.time() - start_time, 3) 

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                parsed_resp = parse_response(str(example_msg))
                return {
                    "token": parsed_resp.get("token", "N/A"),
                    "api": parsed_resp.get("api", "N/A"),
                    "region": parsed_resp.get("region", "N/A"),
                    "status": parsed_resp.get("status", "live"),
                    "Time": f"{elapsed_time} seconds"
                }
            except Exception as e:
                return {"error": f"Failed to deserialize response: {str(e)}", "Time": f"{elapsed_time} seconds"}
        else:
            return {"error": f"HTTP {response.status_code} - {response.reason}", "response": response.text[:200], "Time": f"{elapsed_time} seconds"}

    except requests.RequestException as e:
        elapsed_time = round(time.time() - start_time, 3)
        return {"error": f"Request error: {str(e)}", "Time": f"{elapsed_time} seconds"}

@app.route('/token', methods=['GET'])
def get_token_response():
    """
    Flask endpoint to process GET requests to retrieve a token.
    Requires the query parameters 'uid' and 'password'.
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    if not uid or not password:
        return jsonify({"error": "Missing parameters: uid and password are required"}), 400

    result = process_token(uid, password)

    if "error" in result:
        return jsonify(result), 500

    ordered_result = {
        "token": result.get("token"),
        "api": result.get("api"),
        "region": result.get("region"),
        "status": result.get("status"),
        "developer": "Rasin Bb'z",
        "Time": result.get("Time")
    }

    response = make_response(jsonify(ordered_result))
    response.headers["Content-Type"] = "application/json"
    return response

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "OK", "version": "OB51"}), 200

@app.route('/', methods=['GET'])
def home():
    """Serve the HTML frontend"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Token API Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/axios/1.6.2/axios.min.js"></script>
</head>
<body class="bg-gradient-to-br from-pink-900 via-purple-900 to-indigo-900 min-h-screen">
    <div class="min-h-screen flex items-center justify-center p-4">
        <div class="w-full max-w-md">
            <!-- Header -->
            <div class="text-center mb-8">
                <h1 class="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-pink-300 to-purple-300 mb-2">
                    Token API
                </h1>
                <p class="text-gray-300 text-sm">OB51 Protocol Buffer Gateway</p>
            </div>

            <!-- Main Card -->
            <div class="backdrop-blur-xl bg-white/10 border border-pink-400/20 rounded-2xl p-8 shadow-2xl">
                
                <!-- Input Fields -->
                <div class="space-y-4 mb-6">
                    <!-- UID Input -->
                    <div>
                        <label class="block text-pink-200 text-sm font-medium mb-2">User ID</label>
                        <input 
                            type="text" 
                            id="uid" 
                            placeholder="Enter your UID"
                            class="w-full px-4 py-3 bg-white/5 border border-pink-300/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-pink-400/60 focus:bg-white/10 transition"
                        >
                    </div>

                    <!-- Password Input -->
                    <div>
                        <label class="block text-pink-200 text-sm font-medium mb-2">Password</label>
                        <input 
                            type="password" 
                            id="password" 
                            placeholder="Enter your password"
                            class="w-full px-4 py-3 bg-white/5 border border-pink-300/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-pink-400/60 focus:bg-white/10 transition"
                        >
                    </div>
                </div>

                <!-- Submit Button -->
                <button 
                    onclick="getToken()"
                    id="submitBtn"
                    class="w-full bg-gradient-to-r from-pink-500 to-purple-500 hover:from-pink-600 hover:to-purple-600 text-white font-semibold py-3 rounded-lg transition transform hover:scale-105 active:scale-95 mb-6"
                >
                    Get Token
                </button>

                <!-- Loading State -->
                <div id="loading" class="hidden text-center mb-6">
                    <div class="flex justify-center mb-2">
                        <div class="animate-spin rounded-full h-6 w-6 border-2 border-pink-400 border-t-purple-400"></div>
                    </div>
                    <p class="text-gray-300 text-sm">Processing...</p>
                </div>

                <!-- Result Box -->
                <div id="resultBox" class="hidden bg-white/5 border border-purple-400/30 rounded-lg p-4">
                    <div id="resultContent" class="space-y-3 text-sm"></div>
                </div>

                <!-- Error Box -->
                <div id="errorBox" class="hidden bg-red-500/10 border border-red-400/50 rounded-lg p-4 mb-4">
                    <p id="errorText" class="text-red-300 text-sm"></p>
                </div>
            </div>

            <!-- Footer -->
            <div class="text-center mt-6 text-gray-400 text-xs">
                <p>Secure Protocol Buffer Encryption • AES-256-CBC</p>
            </div>
        </div>
    </div>

    <script>
        async function getToken() {
            const uid = document.getElementById('uid').value.trim();
            const password = document.getElementById('password').value.trim();
            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            const resultBox = document.getElementById('resultBox');
            const errorBox = document.getElementById('errorBox');

  
            resultBox.classList.add('hidden');
            errorBox.classList.add('hidden');

 
            if (!uid || !password) {
                showError('Please enter both UID and Password');
                return;
            }


            submitBtn.disabled = true;
            loading.classList.remove('hidden');

            try {
                const response = await axios.get('/token', {
                    params: { uid, password },
                    timeout: 15000
                });

                const data = response.data;
                console.log('Response data:', data);

                if (data && typeof data === 'object') {
                    if (data.error) {
                        showError(data.error);
                    } else {
                        displayResult(data);
                    }
                } else {
                    showError('Invalid response format');
                }
            } catch (error) {
                console.error('Error:', error);
                if (error.response) {
                    const errData = error.response.data;
                    showError(errData?.error || errData?.message || 'Server error occurred');
                } else if (error.code === 'ECONNABORTED') {
                    showError('Request timeout - server not responding');
                } else {
                    showError('Network error - ' + (error.message || 'unable to connect'));
                }
            } finally {
                submitBtn.disabled = false;
                loading.classList.add('hidden');
            }
        }

        function displayResult(data) {
            const resultBox = document.getElementById('resultBox');
            const resultContent = document.getElementById('resultContent');
            
            let html = '';
            
            const fields = [
                { key: 'status', label: 'Status', icon: '●' },
                { key: 'token', label: 'Token', icon: '🔐' },
                { key: 'api', label: 'API Server', icon: '🌐' },
                { key: 'region', label: 'Region', icon: '🗺️' },
                { key: 'developer', label: 'Developer', icon: '👨‍💻' },
                { key: 'Time', label: 'Response Time', icon: '⏱️' }
            ];

            fields.forEach(field => {
                const value = data[field.key];
                if (value !== undefined && value !== null && value !== '') {
                    let displayValue = String(value);
                    
                    if (field.key === 'token' && displayValue.length > 30) {
                        displayValue = displayValue.substring(0, 30) + '...';
                    }
                    
                    const statusColor = field.key === 'status' && displayValue === 'live' 
                        ? 'text-green-300' 
                        : 'text-gray-300';
                    
                    html += `
                        <div class="flex justify-between items-center">
                            <span class="text-gray-400">${field.icon} ${field.label}</span>
                            <span class="${statusColor} font-mono text-right break-all">${displayValue}</span>
                        </div>
                    `;
                }
            });

            if (html === '') {
                html = '<p class="text-gray-400">No data received</p>';
            }

            resultContent.innerHTML = html;
            resultBox.classList.remove('hidden');
        }

        function showError(message) {
            const errorBox = document.getElementById('errorBox');
            const errorText = document.getElementById('errorText');
            errorText.textContent = message;
            errorBox.classList.remove('hidden');
        }

        document.getElementById('password').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') getToken();
        });

    </script>
</body>
</html>'''

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
