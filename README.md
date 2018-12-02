# Google Rapid Response Automation
Automate GRR forensic analysis


This script automates forensic analysis of multiple machines using GRR API.

- Need to clone grr_api_client folder in the directory for this to work

https://github.com/google/grr/tree/master/api_client/python

### To get started:
- Set up a GRR server.
- Set up a GRR client.
- Update IP address here: sudo nano /etc/grr/server.local.yaml

Update:

```
Client.server_urls: http://http://192.168.1.4:8080/
Frontend.bind_port: '8080'
AdminUI.url: http://192.168.1.4:8000
AdminUI.port
```

restart service: sudo systemctl start grr-server


- Update IP address in client file: /usr/lib/grr/grr_3.2.3.2_amd64/grrd.yaml
_server_urls_
_foreman_check_frequency_


```
Client.foreman_check_frequency: 300
Client.install_path: /usr/lib/%(Client.name)/%(ClientRepacker.output_basename)
Client.name: grr
Client.platform: linux
Client.poll_max: 600
Client.rekall_profile_cache_path: '%(Client.install_path)/rekall_profiles'
Client.server_urls: http://192.168.1.4:8080/

```

restart service:
sudo systemctl start grr

- Provide IP address, user, password to the command

_Start the virtual environment_

source ~/GRR_NEW/bin/activate
