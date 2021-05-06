# Widevine Client 3
This was originally written by T3rry7f. This repo is slightly modified version of his repo. 
<br>This only works on standard Windows!

## Usage

```
usage: wvclient.py [-h] [-site SITE] [-path INIT_PATH] [-pssh PSSH]
                             [-url LICENSE_URL]

origin author is T3rry7f, this is a python3 version.

optional arguments:
  -h, --help            show this help message and exit
  -path INIT_PATH, --init-path INIT_PATH
                        init.mp4 file path
  -pssh PSSH, --pssh PSSH
                        pssh which is base64 format
  -url LICENSE_URL, --license-url LICENSE_URL
                        widevine license server url
  ```

## Instructions
1. Run license_proxy.exe and keep it running in the background!
2. Download content in the MPD Manifest via [widevine-dl](https://github.com/WHTJEON/widevine-dl) (Or you can use other tools to download the encrypted content)
3. Run wvclient3.py 
```
$ python3 wvclient3.py -path 'PATH_TO_DOWNLOADED_CONTENT' -url 'LICENSE_URL'
```
4. Decrypt using mp4decrypt with the keys obtained in the step above.

## Legal Notice
Educational purposes only. Downloading DRM'ed materials may violate their Terms of Service.

##
If you enjoyed using the script, a star or a follow will be highly appreciated! 😎
