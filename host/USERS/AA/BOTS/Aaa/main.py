import requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, base64, datetime, re, socket, threading, ssl, pytz, aiohttp, asyncio, random
from concurrent.futures import ThreadPoolExecutor, as_completed
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import *
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from threading import Thread, Lock
from Pb2 import DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2, MajoRLoGinrEq_pb2, sQ_pb2, Team_msg_pb2
from cfonts import render, say
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global configuration variables
ADMIN_UID = "760840390"
BOT_NAME = "AlliFF BOT"
OWNER_NAME = "AlliFF"
OWNER_TELEGRAM = "@AlliFF_BOT"
HELP_MSG_1 = ""
HELP_MSG_2 = ""
ADMIN_MSG = ""
ONLINE_MSG = ""

def load_config():
    global ADMIN_UID, BOT_NAME, OWNER_NAME, OWNER_TELEGRAM, HELP_MSG_1, HELP_MSG_2, ADMIN_MSG, ONLINE_MSG
    try:
        if os.path.exists('config.json'):
            with open('config.json', 'r', encoding='utf-8') as f:
                config = json.load(f)
                ADMIN_UID = str(config.get('admin_uid', ADMIN_UID))
                BOT_NAME = config.get('bot_name', BOT_NAME)
                OWNER_NAME = config.get('owner_name', OWNER_NAME)
                OWNER_TELEGRAM = config.get('owner_telegram', OWNER_TELEGRAM)
                
                messages = config.get('messages', {})
                HELP_MSG_1 = messages.get('help_msg_1', "")
                HELP_MSG_2 = messages.get('help_msg_2', "")
                # تحسين تحميل الرسائل لتجنب أخطاء التنسيق إذا لم توجد متغيرات
                raw_admin_msg = messages.get('admin_msg', "")
                try:
                    ADMIN_MSG = raw_admin_msg.format(owner_name=OWNER_NAME, owner_telegram=OWNER_TELEGRAM)
                except:
                    ADMIN_MSG = raw_admin_msg
                
                raw_online_msg = messages.get('online_msg', "")
                try:
                    ONLINE_MSG = raw_online_msg.format(bot_name=BOT_NAME, color=get_random_color())
                except:
                    ONLINE_MSG = raw_online_msg
                print(f"[CONFIG] Loaded configuration for {BOT_NAME}")
                return config
    except Exception as e:
        print(f"[CONFIG] Error loading config.json: {e}")
    return {}

server2 = "ME"
key2 = "winter"
BYPASS_TOKEN = ""
attack_running = False
attack_teamcode = None
stop_attack = False
attack_task = None
attack_duration = 45
attack_delay = 0.15

online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False
is_muted = False
mute_until = 0
spam_requests_sent = 0
bot_start_time = time.time()

connection_pool = None
command_cache = {}
last_request_time = {}
RATE_LIMIT_DELAY = 0.1
MAX_CACHE_SIZE = 50
CLEANUP_INTERVAL = 300

command_stats = {}

MK_API_URL = "http://node-mora.naruto-dev.site:20127"
GHOST_API_URL = "http://node-mora.naruto-dev.site:20099/api/ghost"
LAG_GHOST_API_URL = "http://node-mora.naruto-dev.site:20099/api/ghost_attack"
MSG_API_URL = "http://node-mora.naruto-dev.site:20081"
SPAM_API_URL = "http://node-mora.naruto-dev.site:20126"

EMOTE_DATA = None

active_requests = 0
max_concurrent_requests = 5
request_lock = Lock()

LIKE_COOLDOWN = 60
last_like_time = 0
like_cooldown_active = False

maintenance_mode = False

def load_emote_data():
    global EMOTE_DATA
    try:
        with open('emote.json', 'r', encoding='utf-8') as f:
            EMOTE_DATA = json.load(f)
        print(f"[INFO] Loaded {len(EMOTE_DATA)} emotes from emote.json")
    except Exception as e:
        print(f"[ERROR] Failed to load emote.json: {e}")
        EMOTE_DATA = []

def cleanup_cache():
    current_time = time.time()
    to_remove = [k for k, v in last_request_time.items() 
                 if current_time - v > CLEANUP_INTERVAL]
    for k in to_remove:
        last_request_time.pop(k, None)
    
    if len(command_cache) > MAX_CACHE_SIZE:
        oldest_keys = sorted(command_cache.keys())[:len(command_cache)//2]
        for key in oldest_keys:
            command_cache.pop(key, None)

def get_rate_limited_response(user_id):
    user_key = str(user_id)
    current_time = time.time()
    
    if user_key in last_request_time:
        time_since_last = current_time - last_request_time[user_key]
        if time_since_last < RATE_LIMIT_DELAY:
            return False
    
    last_request_time[user_key] = current_time
    return True

async def update_tokens():
    try:
        update_response = requests.get(
            "https://api-like-alliff-v3.vercel.app/reload_tokens",
            timeout=30
        )
        if update_response.status_code == 200:
            data = update_response.json()
            print(f"[TOKEN UPDATE] {data.get('message', 'Tokens updated')}")
            return True
        return False
    except:
        print("[TOKEN UPDATE] Failed to update tokens")
        return False

async def update_tokens_background():
    try:
        await asyncio.sleep(1)
        success = await update_tokens()
        if success:
            print("[BACKGROUND] Tokens updated successfully")
        else:
            print("[BACKGROUND] Token update failed")
    except Exception as e:
        print(f"[BACKGROUND] Error updating tokens: {e}")

async def reset_cooldown_periodically():
    global like_cooldown_active
    while True:
        await asyncio.sleep(30)
        current_time = time.time()
        if like_cooldown_active and current_time - last_like_time >= LIKE_COOLDOWN:
            like_cooldown_active = False
            print("[COOLDOWN] Like cooldown reset - Ready for new requests")

def send_likes(uid):
    global last_like_time, like_cooldown_active
    
    current_time = time.time()
    if like_cooldown_active and current_time - last_like_time < LIKE_COOLDOWN:
        remaining_time = int(LIKE_COOLDOWN - (current_time - last_like_time))
        return f"""[FF0000]❌ Please wait before requesting likes again

[C][B][FF0000]╔══════════╗
[FFFFFF]⚠️ Cooldown Active
[FFFFFF]⚠️ Time remaining: {remaining_time} seconds
[FF0000]╚══════════╝
[FFFFFF]⚡ Please try again in {remaining_time}s"""
    
    try:
        print(f"[DEBUG] Sending like request for UID: {uid}")
        likes_api_response = requests.get(
            f"https://api-like-alliff-v3.vercel.app/like?uid={uid}",
            timeout=30
        )
        
        print(f"[DEBUG] API Response Status: {likes_api_response.status_code}")
        
        if likes_api_response.status_code == 200:
            data = likes_api_response.json()
            print(f"[DEBUG] API Response Data: {data}")
            
            last_like_time = current_time
            like_cooldown_active = True
            
            asyncio.create_task(update_tokens_background())
            
            status = data.get("status")
            
            if status == 1:
                nickname = data.get("PlayerNickname", "Unknown")
                likes_before = data.get("LikesBefore", 0)
                likes_after = data.get("LikesAfter", 0)
                likes_added = data.get("LikesGivenByAPI", 0)
                
                if likes_added == 0:
                    response = f"""[FF0000]⚠️ Sorry, you have reached the maximum limit"""
                else:
                    response = f"""[00FF00]✅ Likes Sent Successfully"""
                
                print(f"[DEBUG] Success response: {response}")
                return response
                
            elif status == 2:
                response = f"""[FF0000]⚠️ Sorry, you have reached the maximum limit"""
                print(f"[DEBUG] Limit response: {response}")
                return response
                
            else:
                response = f"[FF0000]❌ API Error: Status {data.get('status', 'Unknown')}"
                print(f"[DEBUG] API error response: {response}")
                return response
                
        else:
            response = f"[FF0000]Like API Error: {likes_api_response.status_code}"
            print(f"[DEBUG] HTTP error response: {response}")
            return response
            
    except Exception as e:
        response = f"[FF0000]Like API connection failed: {str(e)}"
        print(f"[DEBUG] Connection error response: {response}")
        return response

async def send_emote_packet_fixed(target_uid, emote_id, key, iv, region=None):
    try:
        emote_packet = await send_emote_packet(target_uid, emote_id, key, iv)
        return emote_packet
    except TypeError:
        emote_packet = await send_emote_packet(target_uid, emote_id, key, iv, region)
        return emote_packet

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': 'v1 1',
    'ReleaseVersion': "OB52"
}

def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]", "[7CFC00]", "[B22222]",
        "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]", "[DDA0DD]", "[E6E6FA]",
        "[2E8B57]", "[3CB371]", "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]"
    ]
    return random.choice(colors)

def is_admin(uid):
    return str(uid) == ADMIN_UID

def set_maintenance_mode(enable):
    global maintenance_mode
    maintenance_mode = enable
    return maintenance_mode

def is_maintenance_mode():
    return maintenance_mode

def is_bot_muted():
    global is_muted, mute_until
    if is_muted and time.time() < mute_until:
        return True
    elif is_muted and time.time() >= mute_until:
        is_muted = False
        mute_until = 0
        return False
    return False

def update_command_stats(command):
    if command not in command_stats:
        command_stats[command] = 0
    command_stats[command] += 1

async def check_concurrent_limit():
    global active_requests
    with request_lock:
        if active_requests >= max_concurrent_requests:
            return False
        active_requests += 1
        return True

def release_request():
    global active_requests
    with request_lock:
        if active_requests > 0:
            active_requests -= 1

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    try:
        async with connection_pool.post(url, headers=Hr, data=data) as response:
            if response.status != 200: 
                return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)
    except:
        return (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.120.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    try:
        async with connection_pool.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: 
                return await response.read()
            return None
    except:
        return None


async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    try:
        async with connection_pool.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: 
                return await response.read()
            return None
    except:
        return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: 
        headers = '0000000'
    elif uid_length == 8: 
        headers = '00000000'
    elif uid_length == 10: 
        headers = '000000'
    elif uid_length == 7: 
        headers = '000000000'
    else: 
        print('Unexpected length') 
        headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: 
        return 'Squid'
    elif H == 1: 
        return 'CLan'
    elif H == 2: 
        return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': 
        msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': 
        msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': 
        msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: 
        whisper_writer.write(PacKeT) 
        await whisper_writer.drain()
    elif TypE == 'OnLine': 
        online_writer.write(PacKeT) 
        await online_writer.drain()
    else: 
        return 'UnsoPorTed TypE ! >> ErrrroR (:():)' 

async def handle_friend_request_accepted(inviter_id, key, iv, current_chat_type, current_chat_id):
    welcome_message = f"""[C][B][FFD700]╔══════════════════════════╗
[FFFFFF]Thanks for accepting friend request
[FFFFFF]To know the commands list 
[FFFFFF]Send me any emoji you have 
[FFD700]╠══════════════════════════╣
[FF0000]DEV : @AlliFF_BOT
[FFD700]╚══════════════════════════╝"""
    
    P = await SEndMsG(current_chat_type, welcome_message, inviter_id, current_chat_id, key, iv)
    return P

async def handle_emoji_received(sender_id, key, iv, current_chat_type, current_chat_id):
    response_message = f"""[C][B][00FFFF]────────────────────
[33FFF3][b][c]To know the commands enter:
[99FF80][c][b]/help
[00FFFF]────────────────────
[C][B][FFD700]⚡ Only AlliFF YT 2K
[00FFFF]────────────────────"""
    
    P = await SEndMsG(current_chat_type, response_message, sender_id, current_chat_id, key, iv)
    return P

async def attack_loop(team_code, uid, chat_id, chat_type, key, iv, region):
    global attack_running, stop_attack
    
    print(f"[ATTACK] Starting attack on team {team_code}")
    
    try:
        initial_msg = f"[B][C][FF0000]⚔️ Starting Attack Mode!\n🎯 Target Team: {team_code}\n⏰ Duration: {attack_duration} seconds"
        P = await SEndMsG(chat_type, initial_msg, uid, chat_id, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
        
        start_packet = await FS(key, iv)
        leave_packet = await ExiT(None, key, iv)
        
        attack_start_time = time.time()
        cycle_count = 0
        
        while time.time() - attack_start_time < attack_duration and not stop_attack:
            try:
                join_packet = await GenJoinSquadsPacket(team_code, key, iv)
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
                await asyncio.sleep(0.1)
                
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', start_packet)
                await asyncio.sleep(0.1)
                
                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)
                
                cycle_count += 1
                
                if cycle_count % 10 == 0:
                    elapsed = int(time.time() - attack_start_time)
                    progress_msg = f"[B][C][FFA500]⚔️ Attack Progress\n🔁 Cycles: {cycle_count}\n⏱️ Time: {elapsed}/{attack_duration}s"
                    P = await SEndMsG(chat_type, progress_msg, uid, chat_id, key, iv)
                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                
                await asyncio.sleep(attack_delay)
                
            except Exception as e:
                print(f"[ATTACK] Error in cycle {cycle_count}: {e}")
                await asyncio.sleep(0.5)
        
        if stop_attack:
            completion_msg = f"[B][C][FF0000]🛑 Attack Stopped!\n🎯 Team: {team_code}\n🔁 Cycles Completed: {cycle_count}"
        else:
            completion_msg = f"[B][C][00FF00]✅ Attack Completed!\n🎯 Team: {team_code}\n🔁 Total Cycles: {cycle_count}\n⏱️ Duration: {attack_duration}s"
        
        P = await SEndMsG(chat_type, completion_msg, uid, chat_id, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
        
    except Exception as e:
        print(f"[ATTACK] Error in attack_loop: {e}")
        error_msg = f"[B][C][FF0000]❌ Attack Error: {str(e)}"
        P = await SEndMsG(chat_type, error_msg, uid, chat_id, key, iv)
        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
    
    finally:
        attack_running = False
        stop_attack = False
        print(f"[ATTACK] Attack loop stopped for team {team_code}")

async def handle_ghost_command(target_id, team_code, name, command_type="normal"):
    try:
        if command_type == "normal":
            api_url = f"{GHOST_API_URL}?teamcode={team_code}&name={name}"
        else:
            api_url = f"{LAG_GHOST_API_URL}?teamcode={team_code}&name={name}"
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as temp_session:
            async with temp_session.get(api_url) as resp:
                result = await resp.json()
                return result
    except Exception as e:
        print(f"Error in handle_ghost_command: {e}")
        return {"success": False, "message": str(e)}

async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer , spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , XX , uid , Spy,data2, Chat_Leave
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: 
                    break
                
                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        packet = json.loads(packet)
                        OwNer_UiD , CHaT_CoDe , SQuAD_CoDe = await GeTSQDaTa(packet)

                        JoinCHaT = await AutH_Chat(3 , OwNer_UiD , CHaT_CoDe, key,iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , JoinCHaT)

                        message = f'[B][C]{get_random_color()}\n🎯 AlliFF BOT Online!\n[B][C][00FF00]Commands: Use /help'
                        P = await SEndMsG(0 , message , OwNer_UiD , OwNer_UiD , key , iv)
                        await SEndPacKeT(whisper_writer , online_writer , 'ChaT' , P)

                    except Exception as e:
                        pass

            online_writer.close() 
            await online_writer.wait_closed() 
            online_writer = None

        except Exception as e: 
            print(f"- ErroR With {ip}:{port} - {e}") 
            online_writer = None
        await asyncio.sleep(reconnect_delay)

async def process_command_async(func, *args, **kwargs):
    can_process = await check_concurrent_limit()
    if not can_process:
        return {"status": "busy", "message": "Bot is busy. Please try again later."}
    
    try:
        result = await func(*args, **kwargs)
        return result
    finally:
        release_request()

async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region , reconnect_delay=0.5):
    print(region, 'TCP CHAT')

    global spam_room , whisper_writer , spammer_uid , spam_chat_id , spam_uid , online_writer , chat_id , XX , uid , Spy,data2, Chat_Leave, is_muted, mute_until
    global attack_running, attack_teamcode, stop_attack, attack_task
    
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print('\n - TarGeT BoT in CLan ! ')
                print(f' - Clan Uid > {clan_id}')
                print(f' - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if whisper_writer: 
                    whisper_writer.write(pK) 
                    await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: 
                    break
                
                if data.hex().startswith("120000"):
                    msg = await DeCode_PackEt(data.hex()[10:])
                    chatdata = json.loads(msg)
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        current_uid = response.Data.uid
                        current_chat_id = response.Data.Chat_ID
                        current_chat_type = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower()
                    except:
                        response = None

                    if response:
                        if is_maintenance_mode() and not is_admin(current_uid):
                            P = await SEndMsG(current_chat_type, 
                                f"""[FF0000]❌ Maintenance Mode Active

[C][B][FF0000]╔══════════════════╗
[FFFFFF]⚠️ MAINTENANCE MODE
[FFFFFF]⚠️ Bot is under maintenance
[FFFFFF]⚠️ Please try again later
[FF0000]╚══════════════════╝
[FFFFFF]⚡ Maintenance in progress""", 
                                current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            continue
                        
                        if not get_rate_limited_response(current_uid):
                            continue

                        if is_bot_muted():
                            continue

                        if inPuTMsG.strip() == "" or inPuTMsG.strip().startswith(":") or inPuTMsG.strip().startswith("("):
                            update_command_stats("emoji")
                            print(f'Player {current_uid} sent an emoji')
                            
                            emoji_response = await handle_emoji_received(
                                current_uid, key, iv, 
                                current_chat_type, current_chat_id
                            )
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', emoji_response)
                            continue

                        if inPuTMsG.strip() == "/debug":
                            update_command_stats("debug")
                            debug_msg = f"[FF0000]✅ AlliFF BOT ONLINE! UID: {current_uid}"
                            P = await SEndMsG(current_chat_type, debug_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            continue
                            
                        if inPuTMsG.strip().startswith('/maintenance'):
                            update_command_stats("maintenance")
                            
                            if not is_admin(current_uid):
                                P = await SEndMsG(current_chat_type, 
                                    f"""[FF0000]❌ Unauthorized Access

[C][B][FF0000]╔══════════╗
[FFFFFF]⚠️ Maintenance Mode
[FFFFFF]⚠️ This command is for admin only
[FF0000]╚══════════╝
[FFFFFF]⚡ Contact admin for assistance""", 
                                    current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            
                            set_maintenance_mode(True)
                            
                            P = await SEndMsG(current_chat_type, 
                                f"""[FF0000]✅ Maintenance Mode Activated

[C][B][FF0000]╔══════════════╗
[FFFFFF]⚠️ MAINTENANCE MODE
[FFFFFF]⚠️ Bot is under maintenance
[FF0000]╚══════════════╝
[FFFFFF]⚡ Only admin commands work""", 
                                current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            continue

                        if inPuTMsG.strip().startswith('/unmaintenance'):
                            update_command_stats("unmaintenance")
                            
                            if not is_admin(current_uid):
                                P = await SEndMsG(current_chat_type, 
                                    f"""[FF0000]❌ Unauthorized Access

[C][B][FF0000]╔══════════╗
[FFFFFF]⚠️ Maintenance Mode
[FFFFFF]⚠️ This command is for admin only
[FF0000]╚══════════╝
[FFFFFF]⚡ Contact admin for assistance""", 
                                    current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            
                            set_maintenance_mode(False)
                            
                            P = await SEndMsG(current_chat_type, 
                                f"""[00FF00]✅ Maintenance Mode Deactivated

[C][B][00FF00]╔══════════════════╗
[FFFFFF]✅ MAINTENANCE ENDED
[FFFFFF]✅ Bot is now operational
[00FF00]╚══════════════════╝
[FFFFFF]⚡ All services restored""", 
                                current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            continue
                            
                        if inPuTMsG.strip().startswith('/attack'):
                            update_command_stats("attack")
                            print(f'Processing /attack command from {current_uid}')
                            
                            parts = inPuTMsG.strip().split()
                            if len(parts) < 2:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            else:
                                team_code = parts[1]
                                
                                if not team_code.isdigit():
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                                
                                if attack_running:
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                                
                                stop_attack = False
                                attack_running = True
                                attack_teamcode = team_code
                                
                                attack_task = asyncio.create_task(
                                    attack_loop(team_code, current_uid, current_chat_id, current_chat_type, key, iv, region)
                                )
                                continue
                                
                        if inPuTMsG.strip().startswith('/emote'):
                            update_command_stats("emote")
                            print(f'Processing /emote command from {current_uid}')
                            
                            if not EMOTE_DATA:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            
                            parts = inPuTMsG.strip().split()
                            
                            if len(parts) < 4:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            
                            try:
                                team_code = parts[1]
                                emote_num = parts[2]
                                uids = parts[3:]
                                
                                if not team_code.isdigit():
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                                
                                if not emote_num.isdigit() or not (1 <= int(emote_num) <= 409):
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                                
                                if len(uids) < 1 or len(uids) > 4:
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                                
                                for uid_check in uids:
                                    if not uid_check.isdigit():
                                        P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                        continue
                                
                                emote_id = None
                                emote_num_int = int(emote_num)
                                for emote in EMOTE_DATA:
                                    if int(emote["Number"]) == emote_num_int:
                                        emote_id = emote["Id"]
                                        break
                                
                                if not emote_id:
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                                
                                confirm_msg = f"[B][C][00FF00]⚡ Sending emote {emote_num} to {len(uids)} players..."
                                P = await SEndMsG(current_chat_type, confirm_msg, current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                join_packet = await GenJoinSquadsPacket(team_code, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
                                await asyncio.sleep(2)
                                
                                success_count = 0
                                for target_uid in uids:
                                    try:
                                        emote_packet = await Emote_k(int(target_uid), emote_id, key, iv, region)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', emote_packet)
                                        success_count += 1
                                        await asyncio.sleep(0.5)
                                    except Exception as e:
                                        print(f"Error sending emote to {target_uid}: {e}")
                                
                                leave_packet = await ExiT(None, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)
                                
                                result_msg = f"[B][C][00FF00]✅ Done\n📤 Sent to: {success_count}/{len(uids)} players\n🎭 Emote: {emote_num}"
                                P = await SEndMsG(current_chat_type, result_msg, current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                                
                            except Exception as e:
                                P = await SEndMsG(current_chat_type, f"[B][C][FF0000]❌ ERORR: {str(e)}", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                print(f"Error in /emote command: {e}")
                                continue
                        
                        elif inPuTMsG.strip().startswith('/like '):
                            update_command_stats("like")
                            
                            processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                            P = await SEndMsG(current_chat_type, processing_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            
                            try:
                                parts = inPuTMsG.strip().split()
                                if len(parts) < 2:
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ Please provide UID: /like [uid]", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                                
                                target_uid = parts[1].strip()
                                
                                if target_uid.isdigit():
                                    like_result = send_likes(target_uid)
                                    P = await SEndMsG(current_chat_type, like_result, current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                else:
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ Invalid UID format. UID must be numbers only", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            except Exception as e:
                                print(f"[ERROR] in /like command: {e}")
                                P = await SEndMsG(current_chat_type, f"[B][C][FF0000]❌ Error processing request: {str(e)}", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                        
                        elif inPuTMsG.strip().startswith('/mk'):
                            async def mk_task(user_id, chat_id_param, chat_type_param, msg):
                                update_command_stats("mk")
                                print(f'Processing /mk command from {user_id}')
                                
                                processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                                P = await SEndMsG(chat_type_param, processing_msg, user_id, chat_id_param, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                parts = msg.strip().split()
                                if len(parts) < 2:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                target_id = parts[1]
                                
                                if not target_id.isdigit():
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                try:
                                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as temp_session:
                                        async with temp_session.get(f"{MK_API_URL}/spam?user_id={target_id}", timeout=120) as resp:
                                            result = await resp.json()
                                            
                                            status = result.get("status", "error")
                                            
                                            if status == "success":
                                                P = await SEndMsG(chat_type_param, "[B][C][00FF00]✅ DoNe", user_id, chat_id_param, key, iv)
                                            else:
                                                P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                            
                                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                            return
                                            
                                except asyncio.TimeoutError:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                except Exception as e:
                                    P = await SEndMsG(chat_type_param, f"[B][C][FF0000]❌ ERORR: {str(e)}", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                            
                            asyncio.create_task(process_command_async(mk_task, current_uid, current_chat_id, current_chat_type, inPuTMsG))
                            continue

                        elif inPuTMsG.strip().startswith('/stop_mk'):
                            async def stop_mk_task(user_id, chat_id_param, chat_type_param, msg):
                                update_command_stats("stop_mk")
                                print(f'Processing /stop_mk command from {user_id}')
                                
                                processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                                P = await SEndMsG(chat_type_param, processing_msg, user_id, chat_id_param, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                parts = msg.strip().split()
                                if len(parts) < 2:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                target_id = parts[1]
                                
                                if not target_id.isdigit():
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                try:
                                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as temp_session:
                                        async with temp_session.get(f"{MK_API_URL}/stop?user_id={target_id}", timeout=120) as resp:
                                            result = await resp.json()
                                            
                                            status = result.get("status", "error")
                                            
                                            if status == "success":
                                                P = await SEndMsG(chat_type_param, "[B][C][00FF00]✅ DoNe", user_id, chat_id_param, key, iv)
                                            else:
                                                P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                            
                                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                            return
                                            
                                except asyncio.TimeoutError:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                except Exception as e:
                                    P = await SEndMsG(chat_type_param, f"[B][C][FF0000]❌ ERORR: {str(e)}", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                            
                            asyncio.create_task(process_command_async(stop_mk_task, current_uid, current_chat_id, current_chat_type, inPuTMsG))
                            continue

                        elif inPuTMsG.strip().startswith('/ghost'):
                            async def ghost_task(user_id, chat_id_param, chat_type_param, msg):
                                update_command_stats("ghost")
                                print(f'Processing /ghost command from {user_id}')
                                
                                processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                                P = await SEndMsG(chat_type_param, processing_msg, user_id, chat_id_param, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                parts = msg.strip().split()
                                if len(parts) < 3:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                team_code = parts[1]
                                name = parts[2]
                                
                                if not team_code.isdigit():
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                try:
                                    result = await handle_ghost_command(user_id, team_code, name, "normal")
                                    
                                    if result.get("success"):
                                        P = await SEndMsG(chat_type_param, "[B][C][00FF00]✅ DoNe", user_id, chat_id_param, key, iv)
                                    else:
                                        P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                            
                                except asyncio.TimeoutError:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                except Exception as e:
                                    P = await SEndMsG(chat_type_param, f"[B][C][FF0000]❌ ERORR: {str(e)}", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                            
                            asyncio.create_task(process_command_async(ghost_task, current_uid, current_chat_id, current_chat_type, inPuTMsG))
                            continue

                        elif inPuTMsG.strip().startswith('/lag_ghost'):
                            async def lag_ghost_task(user_id, chat_id_param, chat_type_param, msg):
                                update_command_stats("lag_ghost")
                                print(f'Processing /lag_ghost command from {user_id}')
                                
                                processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                                P = await SEndMsG(chat_type_param, processing_msg, user_id, chat_id_param, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                parts = msg.strip().split()
                                if len(parts) < 3:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                team_code = parts[1]
                                name = parts[2]
                                
                                if not team_code.isdigit():
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                try:
                                    result1 = await handle_ghost_command(user_id, team_code, name, "lag")
                                    
                                    processing_msg2 = "[B][C][FFFF00]⏳ Please wait 5 seconds for the second request..."
                                    P = await SEndMsG(chat_type_param, processing_msg2, user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    
                                    await asyncio.sleep(5)
                                    
                                    result2 = await handle_ghost_command(user_id, team_code, name, "lag")
                                    
                                    if result1.get("success") or result2.get("success"):
                                        P = await SEndMsG(chat_type_param, "[B][C][00FF00]✅ DoNe", user_id, chat_id_param, key, iv)
                                    else:
                                        P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                            
                                except asyncio.TimeoutError:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                except Exception as e:
                                    P = await SEndMsG(chat_type_param, f"[B][C][FF0000]❌ ERORR: {str(e)}", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                            
                            asyncio.create_task(process_command_async(lag_ghost_task, current_uid, current_chat_id, current_chat_type, inPuTMsG))
                            continue

                        elif inPuTMsG.strip().startswith('/msg'):
                            async def msg_task(user_id, chat_id_param, chat_type_param, msg):
                                update_command_stats("msg")
                                print(f'Processing /msg command from {user_id}')
                                
                                processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                                P = await SEndMsG(chat_type_param, processing_msg, user_id, chat_id_param, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                parts = msg.strip().split()
                                if len(parts) < 3:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                team_code = parts[1]
                                message = ' '.join(parts[2:])
                                
                                if not team_code.isdigit():
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                try:
                                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as temp_session:
                                        async with temp_session.get(f"{MSG_API_URL}/msg?teamcode={team_code}&msg={message}", timeout=120) as resp:
                                            result = await resp.json()
                                            
                                            xS = result.get("xS", False)
                                            
                                            if xS:
                                                P = await SEndMsG(chat_type_param, "[B][C][00FF00]✅ DoNe", user_id, chat_id_param, key, iv)
                                            else:
                                                P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                            
                                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                            return
                                            
                                except asyncio.TimeoutError:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                except Exception as e:
                                    P = await SEndMsG(chat_type_param, f"[B][C][FF0000]❌ ERORR: {str(e)}", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                            
                            asyncio.create_task(process_command_async(msg_task, current_uid, current_chat_id, current_chat_type, inPuTMsG))
                            continue

                        elif inPuTMsG.strip().startswith('/spam'):
                            async def spam_task(user_id, chat_id_param, chat_type_param, msg):
                                update_command_stats("spam")
                                print(f'Processing /spam command from {user_id}')
                                
                                processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                                P = await SEndMsG(chat_type_param, processing_msg, user_id, chat_id_param, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                parts = msg.strip().split()
                                if len(parts) < 2:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                target_id = parts[1]
                                
                                if not target_id.isdigit():
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                try:
                                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as temp_session:
                                        async with temp_session.get(f"{SPAM_API_URL}/spam?user_id={target_id}", timeout=120) as resp:
                                            result = await resp.json()
                                            
                                            status = result.get("status", "error")
                                            
                                            if status == "success":
                                                P = await SEndMsG(chat_type_param, "[B][C][00FF00]✅ DoNe", user_id, chat_id_param, key, iv)
                                            else:
                                                P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                            
                                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                            return
                                            
                                except asyncio.TimeoutError:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                except Exception as e:
                                    P = await SEndMsG(chat_type_param, f"[B][C][FF0000]❌ ERORR: {str(e)}", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                            
                            asyncio.create_task(process_command_async(spam_task, current_uid, current_chat_id, current_chat_type, inPuTMsG))
                            continue

                        elif inPuTMsG.strip().startswith('/stop_spam'):
                            async def stop_spam_task(user_id, chat_id_param, chat_type_param, msg):
                                update_command_stats("stop_spam")
                                print(f'Processing /stop_spam command from {user_id}')
                                
                                processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                                P = await SEndMsG(chat_type_param, processing_msg, user_id, chat_id_param, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                parts = msg.strip().split()
                                if len(parts) < 2:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                target_id = parts[1]
                                
                                if not target_id.isdigit():
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                
                                try:
                                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as temp_session:
                                        async with temp_session.get(f"{SPAM_API_URL}/stop?user_id={target_id}", timeout=120) as resp:
                                            result = await resp.json()
                                            
                                            status = result.get("status", "error")
                                            
                                            if status == "success":
                                                P = await SEndMsG(chat_type_param, "[B][C][00FF00]✅ DoNe", user_id, chat_id_param, key, iv)
                                            else:
                                                P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                            
                                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                            return
                                            
                                except asyncio.TimeoutError:
                                    P = await SEndMsG(chat_type_param, "[B][C][FF0000]❌ ERORR", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                                except Exception as e:
                                    P = await SEndMsG(chat_type_param, f"[B][C][FF0000]❌ ERORR: {str(e)}", user_id, chat_id_param, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    return
                            
                            asyncio.create_task(process_command_async(stop_spam_task, current_uid, current_chat_id, current_chat_type, inPuTMsG))
                            continue

                        elif inPuTMsG.startswith("/admin"):
                            update_command_stats("admin")
                            print(f"Help triggered by {current_uid}")
                            
                            processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                            P = await SEndMsG(current_chat_type, processing_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            
                            if is_admin(current_uid):
                                # استخدام الرسالة من الإعدادات لتمكين التحديث التلقائي
                                base_msg = ADMIN_MSG if ADMIN_MSG else f"""[C][B][FF0000]╔══════════╗
[FFFFFF]✨ folow on Telegram    
[FFFFFF]          ⚡ @AlliFF_BOT_V1
[FFFFFF]                   thank for support 
[FF0000]╠══════════╣
[FFD700]⚡ OWNER : [FFFFFF]AlliFF    
[FFD700]✨ Name on Telegram  : [FFFFFF]@AlliFF_BOT  
[FF0000]╚══════════╝
[FFD700]✨ Developer —͟͞͞ </> AlliFF ⚡"""
                                message = base_msg + f"""

[C][B][00FF00]╔══════════════╗
[FFFFFF]⚡ Admin Commands:
[FFFFFF]⚡ /maintenance - Enable maintenance
[FFFFFF]⚡ /unmaintenance - Disable maintenance
[FFFFFF]⚡ /stop - Stop the bot
[00FF00]╚══════════════╝"""
                            else:
                                # استخدام الرسالة من الإعدادات لتمكين التحديث التلقائي
                                message = ADMIN_MSG if ADMIN_MSG else f"""[C][B][FF0000]╔══════════╗
[FFFFFF]✨ folow on Telegram    
[FFFFFF]          ⚡ @AlliFF_BOT_V1
[FFFFFF]                   thank for support 
[FF0000]╠══════════╣
[FFD700]⚡ OWNER : [FFFFFF]AlliFF    
[FFD700]✨ Name on Telegram  : [FFFFFF]@AlliFF_BOT  
[FF0000]╚══════════╝
[FFD700]✨ Developer —͟͞͞ </> AlliFF ⚡"""
                            
                            try:
                                P = await SEndMsG(current_chat_type, message, current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            except Exception as e:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                        
                        if inPuTMsG.startswith('/stop') and is_admin(current_uid):
                            update_command_stats("stop")
                            P = await SEndMsG(current_chat_type, "[B][C][00FF00]✅ DoNe", current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            await connection_pool.close()
                            os._exit(0)
                        
                        elif inPuTMsG.startswith('/like/'):
                            update_command_stats("like")
                            
                            processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                            P = await SEndMsG(current_chat_type, processing_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            
                            try:
                                target_uid = inPuTMsG.split('/like/')[1].strip()
                                if target_uid.isdigit():
                                    like_result = send_likes(target_uid)
                                    P = await SEndMsG(current_chat_type, like_result, current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                                else:
                                    P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                    continue
                            except:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                                
                        elif inPuTMsG.startswith('/3') or inPuTMsG.startswith('/5') or inPuTMsG.startswith('/6'):
                            update_command_stats("squad_create")
                            
                            processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                            P = await SEndMsG(current_chat_type, processing_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            
                            try:
                                squad_size = int(inPuTMsG[1])
                                
                                message = f"[B][C]{get_random_color()}\n🎯 {squad_size}-Player Squad!\nAccept Fast"
                                P = await SEndMsG(current_chat_type, message, current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                
                                PAc = await OpEnSq(key, iv, region)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', PAc)
                                C = await cHSq(squad_size, current_uid, key, iv, region)
                                await asyncio.sleep(0.3)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', C)
                                V = await SEnd_InV(squad_size, current_uid, key, iv, region)
                                await asyncio.sleep(0.3)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', V)
                                E = await ExiT(None, key, iv)
                                await asyncio.sleep(2)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', E)
                                
                                P = await SEndMsG(current_chat_type, "[B][C][00FF00]✅ DoNe", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                            except Exception as e:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                                
                        elif inPuTMsG.startswith('/solo'):
                            update_command_stats("solo")
                            
                            processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                            P = await SEndMsG(current_chat_type, processing_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            
                            try:
                                P = await SEndMsG(current_chat_type, "[B][C][00FF00]✅ DoNe", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                leave = await ExiT(current_uid, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave)
                                continue
                            except:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue

                        elif inPuTMsG.strip().startswith('/boost'):
                            update_command_stats("speed")
                            
                            processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                            P = await SEndMsG(current_chat_type, processing_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            
                            try:
                                P = await SEndMsG(current_chat_type, "[B][C][00FF00]✅ DoNe", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                EM = await FS(key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', EM)
                                continue
                            except:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue

                        elif inPuTMsG.strip().startswith('/help'):
                            update_command_stats("help")
                            
                            processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                            P = await SEndMsG(current_chat_type, processing_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            
                            try:
                                message1 = f"""[C][B][ADD8E6]═══AlliFF BOT |
[E0FFFF]⚡ For emote without bot
[AFEEEE]⚡ /emote [team_code] [emote_number] [uid1] [uid2] [uid3] [uid4]

[E0FFFF]⚡ Send likes to player
[AFEEEE]⚡ /like [uid]

[E0FFFF]⚡ Create 5 player squad
[AFEEEE]⚡ /5

[E0FFFF]⚡ Create 6 player squad
[AFEEEE]⚡ /6

[E0FFFF]⚡ Create 3 player squad
[AFEEEE]⚡ /3

[E0FFFF]⚡ Intensive attack (45 seconds)
[AFEEEE]⚡ /attack [team_code]

[E0FFFF]⚡ Stop attack
[AFEEEE]⚡ /stop_attack

[AFEEEE]━━━━━━━━━━━━[E0FFFF]"""
                                
                                message2 = f"""[C][B][FFD700] AlliFF BOT | [FFFF00][B]

[FFFF00]⚡ Return bot to solo
[00FFFF]⚡ /solo

[FFFF00]⚡ Know who is admin
[00FFFF]⚡ /Admin

[FFFF00]⚡ Room invites spam
[00FFFF]⚡ /mk [id]

[FFFF00]⚡ Stop room spam
[00FFFF]⚡ /stop_mk [id]

[FFFF00]⚡ Send ghosts to team
[00FFFF]⚡ /ghost [team_code] [name]

[FFFF00]⚡ Lag attack on team
[00FFFF]⚡ /lag_ghost [team_code] [name]

[FFFF00]⚡ Messages in team
[00FFFF]⚡ /msg [team_code] [message]

[FFFF00]⚡ Squad spam
[00FFFF]⚡ /spam [id]

[FFFF00]⚡ Stop spam
[00FFFF]⚡ /stop_spam [id]

[FFFF00]⚡ Note: This bot is not complete, working on adding remaining commands

[00FFFF]━━━━━━━━━━━━[FFFF00]"""

                                P1 = await SEndMsG(current_chat_type, message1, current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P1)
                                
                                await asyncio.sleep(0.5)
                                
                                P2 = await SEndMsG(current_chat_type, message2, current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P2)
                                continue
                            except:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue
                        
                        elif inPuTMsG.startswith('/join '):
                            update_command_stats("join_squad")
                            
                            processing_msg = "[B][C][FFFF00]⏳ Processing your request..."
                            P = await SEndMsG(current_chat_type, processing_msg, current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            
                            try:
                                Code = inPuTMsG.split('/join ')[1]
                                P = await SEndMsG(current_chat_type, "[B][C][00FF00]✅ DoNe", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                EM = await GenJoinSquadsPacket(Code, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', EM)
                                continue
                            except:
                                P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                continue

                        elif inPuTMsG.startswith('/'):
                            update_command_stats("unknown")
                            P = await SEndMsG(current_chat_type, "[B][C][FF0000]❌ ERORR", current_uid, current_chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            continue
                            
            whisper_writer.close() 
            await whisper_writer.wait_closed() 
            whisper_writer = None
                    	
        except Exception as e: 
            print(f"ErroR {ip}:{port} - {e}") 
            whisper_writer = None
        await asyncio.sleep(reconnect_delay)

async def MaiiiinE():
    global connection_pool
    connection_pool = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=20),
        connector=aiohttp.TCPConnector(limit=20, limit_per_host=10)
    )
    
    load_emote_data()
    config = load_config()
    
    Uid = str(config.get('account_uid', ''))
    Pw = str(config.get('account_password', ''))

    if not Uid or not Pw:
        print("ErroR - Account UID or Password not found in config.json")
        await connection_pool.close()
        return None

    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: 
        print("ErroR - InvaLid AccounT") 
        await connection_pool.close()
        return None
    
    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: 
        print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ") 
        await connection_pool.close()
        return None
    
    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(f"URL: {UrL}")
    region = MajoRLoGinauTh.region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp
    
    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: 
        print("ErroR - GeTinG PorTs From LoGin DaTa !") 
        await connection_pool.close()
        return None
        
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    
    try:
        OnLineParts = OnLinePorTs.split(":")
        if len(OnLineParts) >= 2:
            OnLineiP = OnLineParts[0]
            OnLineporT = OnLineParts[1]
        else:
            print(f"Invalid Online Ports format: {OnLinePorTs}")
            await connection_pool.close()
            return None
            
        ChaTParts = ChaTPorTs.split(":")
        if len(ChaTParts) >= 2:
            ChaTiP = ChaTParts[0]
            ChaTporT = ChaTParts[1]
        else:
            print(f"Invalid Chat Ports format: {ChaTPorTs}")
            await connection_pool.close()
            return None
    except Exception as e:
        print(f"Error splitting ports: {e}")
        await connection_pool.close()
        return None
    
    acc_name = LoGinDaTaUncRypTinG.AccountName
    print(f"Token: {ToKen}")
    print(f"Online: {OnLineiP}:{OnLineporT}")
    print(f"Chat: {ChaTiP}:{ChaTporT}")
    
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , key , iv)
    ready_event = asyncio.Event()
    
    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , key , iv , LoGinDaTaUncRypTinG , ready_event ,region))
     
    await ready_event.wait()
    await asyncio.sleep(1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , key , iv , AutHToKen))
    os.system('clear')
    print(render('AlliFF', colors=['white', 'green'], align='center'))
    print('')
    print(f" - AlliFF BOT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n")
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")    
    print(f" - winter | Bot Uptime: {time.strftime('%H:%M:%S', time.gmtime(time.time() - bot_start_time))}")    
    await asyncio.gather(task1 , task2)
    
async def watch_config():
    """يراقب ملف config.json ويقوم بتحديث الإعدادات فور تغييرها"""
    last_mtime = 0
    if os.path.exists('config.json'):
        last_mtime = os.path.getmtime('config.json')
    
    while True:
        try:
            await asyncio.sleep(2)  # فحص كل ثانيتين
            if os.path.exists('config.json'):
                current_mtime = os.path.getmtime('config.json')
                if current_mtime > last_mtime:
                    print("[WATCHER] Config file changed, reloading...")
                    load_config()
                    last_mtime = current_mtime
        except Exception as e:
            print(f"[WATCHER] Error: {e}")

async def StarTinG():
    cooldown_task = asyncio.create_task(reset_cooldown_periodically())
    watcher_task = asyncio.create_task(watch_config())
    
    while True:
        try: 
            await asyncio.wait_for(MaiiiinE() , timeout = 7 * 60 * 60)
        except asyncio.TimeoutError: 
            print("Token ExpiRed ! , ResTartinG")
        except Exception as e: 
            print(f"ErroR TcP - {e} => ResTarTinG ...")
        finally:
            if connection_pool:
                await connection_pool.close()
            cooldown_task.cancel()

if __name__ == '__main__':
    asyncio.run(StarTinG())