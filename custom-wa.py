#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth

# Membaca konfigurasi
alert_file = open(sys.argv[1])
hook_url = sys.argv[3]

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
headers = {
    'Content-Type': 'application/json',
    'Accept-Charset': 'UTF-8'
}

if int(alert_level) < 6 and "block" in title.lower():
    msg_data['msg'] = f'*WAZUH BLOCK NOTIFICATION*\n- *Title*: {title}\n- Level: {alert_level}\n- IP SRC: {target_ip}\n- Groups: {groups}\n- *Agent*: {agent_name} ({agent_id})\n\n{description}'
    # Mengirimkan permintaan ke server bot
    requests.post(hook_url, headers=headers, data=json.dumps(msg_data))
elif int(alert_level) >= 6 and 'scp' not in groups.lower():
    msg_data['msg'] = f'*WAZUH ALERT NOTIFICATION*\n- *Title*: {title}\n- Level: {alert_level}\n- IP SRC: {target_ip}\n- Groups: {groups}\n- *Agent*: {agent_name} ({agent_id})\n\n{description}'
    # Mengirimkan permintaan ke server bot
    requests.post(hook_url, headers=headers, data=json.dumps(msg_data))


sys.exit(0)
