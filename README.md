### Threat Response Get SHA256 Disposition

This script queries the Threat Response API for the dispostion of a SHA256. If a SHA256 is not provided as a command line argument, the script will prompt for one. An access token will be generated as needed and written to disk for storage. If the token is not found or is invalid a new one will be generated automatically.

### Before using you must update the following
- CLIENT_ID
- CLIENT_PASSWORD

### Usage
```
python get_sha256_disposition.py
```
or
```
python get_sha256_disposition.py 630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da
```

### Example script output:  
```
python get_sha256_disposition.py 630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da
AMP File Reputation    2    Malicious    630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da
AMP Global Intel       2    Malicious    630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da
VirusTotal             2    Malicious    630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da
```
