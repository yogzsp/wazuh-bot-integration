#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth

def sendNotification(hook_url, msg_data):
    headers = {
        'Content-Type': 'application/json',
        'Accept-Charset': 'UTF-8'
    }
    # Mengirimkan permintaan ke server bot
    requests.post(hook_url, headers=headers, data=json.dumps(msg_data))

def getInformationDataNotification(alert_file_path):
    # Membaca konfigurasi
    alert_file = open(alert_file_path)

    # Membaca peringatan pada file
    alert_json = json.load(alert_file)
    alert_file.close()

    # Ekstrak data field
    title = alert_json['rule']['description'] if 'description' in alert_json['rule'] else ''
    description = alert_json['full_log'] if 'full_log' in alert_json else ''
    description = description.replace("\\n", "\n")  # Perbaikan penggantian karakter
    alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else ''
    groups = ', '.join(alert_json['rule']['groups']) if 'groups' in alert_json['rule'] else ''
    rule_id = alert_json['rule']['id'] if 'id' in alert_json['rule'] else ''
    agent_name = alert_json['agent']['name'] if 'name' in alert_json['agent'] else ''
    agent_id = alert_json['agent']['id'] if 'id' in alert_json['agent'] else ''
    target_ip = alert_json['data']['srcip'] if 'srcip' in alert_json['data'] else ''

    # Menyiapkan data pesan untuk dikirim ke server bot
    msg_data = {}

    if int(alert_level) < 6 and "block" in title.lower():
        msg_data['msg'] = f'*WAZUH BLOCK NOTIFICATION*\n- *Title*: {title}\n- Level: {alert_level}\n- IP SRC: {target_ip}\n- Groups: {groups}\n- *Agent*: {agent_name} ({agent_id})\n\n{description}'
    elif int(alert_level) >= 6:
        msg_data['msg'] = f'*WAZUH ALERT NOTIFICATION*\n- *Title*: {title}\n- Level: {alert_level}\n- IP SRC: {target_ip}\n- Groups: {groups}\n- *Agent*: {agent_name} ({agent_id})\n\n{description}'

    return msg_data

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py <alert_file> <username> <hook_url>")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    hook_url = sys.argv[3]

    msg_data = getInformationDataNotification(alert_file_path)
    
    if "msg" in msg_data:
        sendNotification(hook_url, msg_data)
