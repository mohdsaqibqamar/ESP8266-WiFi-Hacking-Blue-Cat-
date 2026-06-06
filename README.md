# Blue Wifi Cat ESP8266 & Deauther

An advanced, feature-rich Wi-Fi auditing and penetration testing tool designed specifically for the ESP8266 microcontroller. This project provides an all-in-one control panel for network analysis, deauthentication attacks, evil twin phishing, and even acts as a Wi-Fi repeater. It features a sleek "Neon" dark-themed UI.

LiveWeb:- https://raw.githack.com/mohdsaqibqamar/ESP8266-WiFi-Hacking-Blue-Cat-/refs/heads/main/Website/index.html

---

## ⚡ Features & Usage

### 1. Target Scanning
Scan the surrounding area for available Wi-Fi access points. The control panel will populate a table with the SSID, BSSID (MAC Address), and Channel of nearby networks.

### 2. Deauthentication (Deauth) Attack
Disconnect users from a targeted Wi-Fi network by sending forged deauthentication frames. This attack forces clients to disconnect, which is useful for capturing handshakes or forcing them to connect to your Evil Twin AP.
* **Usage:** Select a target network from the table and click **START DEAUTH**.

### 3. Evil Twin (Phishing Hotspot)
Clones the target's Wi-Fi name (SSID) and creates an open access point with the exact same name. When victims connect, they are presented with a Captive Portal (Phishing Page) asking for their Wi-Fi password to "install a firmware update."
* **Usage:** Select a target and click **START EVILTWIN**.

### 4. Custom Phishing Templates
The captive portal page is fully customizable. You don't have to stick with the default router firmware update page.
* **Download Default:** Download the default HTML template to your PC to modify it.
* **Upload Custom HTML:** Upload your edited HTML file directly to the ESP8266. You can use the `{{WIFI_NAME}}` placeholder in your HTML, and the ESP8266 will automatically replace it with the target AP's name.
* **One-Time Use:** Custom templates are stored in LittleFS and are automatically wiped when the ESP8266 is restarted, keeping the system clean.

### 5. Recovered Password Management
When a victim enters their password into the captive portal, it is saved directly to the ESP8266's persistent memory (EEPROM).
* **View:** Passwords are automatically displayed in the **RECOVERED PASSWORD** panel.
* **Delete:** Use the **DELETE PASSWORD** button to wipe the captured password from memory and free up space for future attacks.

### 6. Wi-Fi Repeater (NAPT)
Turns your ESP8266 into a fully functional Wi-Fi range extender using Network Address Port Translation (NAPT). 
* **Usage:** Select your home Wi-Fi, enter the password, and provide a name and password for your new Extender network. The ESP8266 will bridge the connection and provide internet access to devices connected to it.

### 7. Random Beacon Spam
Flood the area with dozens of fake Wi-Fi networks (SSIDs) to confuse users or hide your actual malicious network among the noise.

---

## Step-by-Step Installation Guide (Super Easy!)

Don't worry if you are completely new to this! Just follow these easy steps like a recipe, and you'll have your **Blue Wifi Cat** running in no time.

### Step 1: Get the Software (Arduino IDE)
1. Go to [arduino.cc/en/software](https://www.arduino.cc/en/software) on your computer.
2. Download and install the **Arduino IDE** (just click "Next" until it's installed).
3. Open the Arduino IDE software.

### Step 2: Add the Magic Link
We need to tell Arduino how to understand our hacking code.
1. Click on **File** at the top left, then click **Preferences**.
2. Look for a box that says **"Additional Boards Manager URLs"**.
3. Copy and paste this exact link into that box:
   `https://raw.githubusercontent.com/SpacehuhnTech/arduino/main/package_spacehuhn_index.json`
4. Click **OK**.

### Step 3: Download the Deauther Package
1. Click on **Tools** -> **Board** -> **Boards Manager**.
2. A search bar will appear on the left. Type **"deauther"** in it.
3. You will see a package named **ESP8266 Deauther**. Click the **INSTALL** button next to it. Wait a minute for it to finish.

### Step 4: Setup the Correct Settings for Repeater
This step is super important so the Wi-Fi Repeater works fast!
1. Go to **Tools** -> **Board** -> **ESP8266 Deauther Modules**.
2. Select **Generic ESP8266 Module** from the list.
3. Now go back to **Tools** and look for **LwIP Variant**. 
4. Click it and select **v2 Higher Bandwidth**. (This makes the internet speed fast when using the repeater feature).

### Step 5: Connect and Upload!
1. Plug your ESP8266 into your computer using a USB data cable.
2. In Arduino, go to **Tools** -> **Port** and select the COM port that just appeared (e.g., COM3 or COM4).
3. Open the `sketch_jun01a.ino` file if you haven't already.
4. Click the **Upload Button** (it looks like a right arrow `->` at the top left).
5. Wait a few minutes. When the text at the bottom says **"Done uploading"**, you are finished!

---

## 💻 Accessing the Control Panel

Once the upload is done:
1. Connect your phone or PC to the Wi-Fi network named **Syper** (Password: `Syper@786`).
2. Open Google Chrome.
3. Type `http://192.168.4.1/admin` in the search bar at the top and press Enter.
4. Log in using the password: `Syper@786`.
5. Welcome to the **Blue Wifi Cat** control panel!

---

## 🛠️ Troubleshooting (Fix "Choose File" Issue)

If the **Choose File** button is not working on your phone while uploading a Custom Template, it is because of the Android Captive Portal limitations. Use this method to fix it:

1. Connect to the ESP8266 Wi-Fi network from your phone.
2. When the auto-popup window *(Sign in to Wi-Fi)* appears, **Close** it, or click the top-right 3-dots menu and select **"Use this network as is"** / **"Keep Wi-Fi Connection"**.
3. Now, open your **Google Chrome** (or Safari) browser normally.
4. Type `192.168.4.1/admin` in the address bar and press enter.

---

*Disclaimer: This tool is intended for educational purposes and authorized auditing only. Usage of this tool against networks you do not own or do not have explicit permission to audit is illegal. The author assumes no liability for misuse.*
