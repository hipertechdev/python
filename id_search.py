#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import ftplib
import socket

# FTP credentials
ftp_address = "192.168.0.20"
ftp_port = 21
ftp_username = "aepel"
ftp_password = "aepel"

# Local file paths
sip_file_path = "/var/www/html/sip.txt"
volume_level_path = "/var/www/html/dv.txt"
bgm_status_path = "/var/www/html/bgm_setup.txt"
id_file_path = "/home/{}_id.txt"

# Get the MAC address
mac_address = os.popen('ifconfig | grep "HWaddr" | awk \'{print $NF}\'').read().strip().upper()

# Get the local IP address
def get_local_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip_address = s.getsockname()[0]
    s.close()
    return local_ip_address

# Check the current IP addresses and save them to a file
def save_ip_addresses():
    public_ip_address = os.popen('curl ifconfig.me').read().strip()
    local_ip_address = get_local_ip_address()
    with open(id_file_path.format(sip_content), "w") as f:
        f.write("SIP Number: {}\nMAC address: {}\nPublic IP address: {}\nLocal IP address: {}\nVolume Level: {}\nBGM Status: {}".format(sip_content, mac_address, public_ip_address, local_ip_address, volume_level, bgm_status))

# Connect to FTP server and upload the file
def upload_file():
    ftp = ftplib.FTP()
    ftp.connect(ftp_address, ftp_port)
    ftp.login(user=ftp_username, passwd=ftp_password)
    ftp.cwd("/home")
    with open(id_file_path.format(sip_content), "rb") as f:
        try:
            ftp.storbinary("STOR {}_id.txt".format(sip_content), f)
        except Exception as e:
            print("Error uploading file:", e)
    ftp.quit()

# Read the first part of the sip.txt file
with open(sip_file_path, "r") as f:
    sip_content = f.readline().strip().split(",")[0]

# Check the IP addresses every 30 seconds and update the file if changed
previous_public_ip_address = ""
previous_local_ip_address = ""
previous_volume_level = ""
previous_bgm_status = ""
while True:
    current_public_ip_address = os.popen('curl ifconfig.me').read().strip()
    current_local_ip_address = get_local_ip_address()
    with open(volume_level_path, "r") as vl:
        volume_level = vl.read().strip()
    with open(bgm_status_path, "r") as bs:
        bgm_status = bs.read().strip()
    if current_public_ip_address != previous_public_ip_address or current_local_ip_address != previous_local_ip_address or volume_level != previous_volume_level or bgm_status != previous_bgm_status:
        save_ip_addresses()
        time.sleep(10) # Add a delay before uploading the file to allow the system to stabilize
        try:
            upload_file()
        except Exception as e:
            print("Error uploading file:", e)
        else:
            previous_public_ip_address = current_public_ip_address # Only update previous IP addresses if file upload was successful
            previous_local_ip_address = current_local_ip_address
    time.sleep(30)