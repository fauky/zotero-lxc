## Selfhost Zotero Dataserver and Web Library in Proxmox LXC Container

## About
This repository contains a single script for selfhosting zotero backend services in an all-in-one LXC container. It has been tested in an Ubuntu 24.04 LXC on Proxmox.

### What is included

The following services are installed by this script.

| Service                | Description                                      |
|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Data Server**        | The backbone of Zotero backend                                                                                                                        |
| **Web Library**        | Provides access to Zotero Library via Web Browser                                                                                                     |
| **Attachment Proxy**   | Allows for editing/downloading attachments in the Web Library                                                                                         |
| **Stream Server**      | Provides Websocket connections to Web Browser and desktop clients for realtime synchronization                                                        |
| **Fulltext Indexer**   | Indexes extracted text from file attachments in elasticsearch for full text searching via Web Library and Desktop Clients                             |
| **Translation Server** | This should be parsing articles sent by the browser extension, but  this project does not rebuild browser extension, so this is dormant at the moment |
| **MinIO**              | Provides storage for files/snapshots attachments                                                                                                      |
| **Elastic Search**     | Provide full text search capabilities in Web Library for file attachments                                                                             |


## Installation
Though this script has only been tested in an Ubuntu 24.04 LXC on Proxmox 8.4.1, it should technically install on a bare metal  Ubuntu 24.04 Desktop/Server too.

To selfhost zotero, simply download this script and execute with root or sudo.

```
sudo ./zotero-lxc.sh
```

Or simply run the following commands inside the LXC container to download and run the script in one go:

```
# install curl
apt update && apt install -y curl

# install zotero
bash -c "$(curl -fsSL https://raw.githubusercontent.com/fauky/zotero-lxc/main/zotero-lxc.sh)"
```

### User Input During Installation
The script prompts for the following information right in the beginning:

#### Protocol
This can either be HTTP or HTTPS, but once everything is installed, it cannot be changed easily since it is hard-coded in many places in zotero source code, therefore, choose wisely.

Select HTTPS if you have a public domain name and would like to put a reverse proxy in front of your server.

Select HTTP if you are hosting it locally and do not need SSL encryption. Please do note that the username/password and the generated api tokens will be visible in plain-text should you choose HTTP.

You can also select HTTPS even if you are hosting it locally and do not have a public domain name. The script will generate self-signed SSL certificate and configure apache to provide access to all services via SSL. This should take care of the passwords leaking out in plain-text.

Web Browsers will raise a warning for self-signed certificates when you access your Web Library via HTTPS for the first time, but it will also allow you to add an exception.

Zotero Desktop Clients do not provide a method to accept self-signed certificates at runtime. The clients require placing of a **cert_override.txt** file in the client's profile directory with the signature of the generated self-signed certificate to allow it to work with self-signed certificates. This script, fortunately, also generates additional scripts (mentioned below) which take care of this step automatically.

#### Domain
Domain name is also hard-coded in zotero sources and cannot be changed easily after installation. Therefore, it is important to make the right choice here.

If you have a public domain name and would like to host zotero behind a reverse proxy like caddy or nginx, please use your actual domain name here.

If you are hosting it locally, you can either use the suggested hostname as domain, provide a domain name manually, or even choose the IP address of the server as the domain. If you choose the hostname or provide a domain name, you would either have to set up your own DNS server in your local LAN environment, or create entries in `/etc/hosts` or `C:\Windows\System32\drivers\etc\hosts` files on each Linux and Windows system that you would access this server from.

Choosing IP address as a domain name makes it easy for the desktop clients to connect to your server since you wouldn't need to set up a local DNS server or create hosts file entries. Please do make sure to set up a static IP address on the server prior to install. The script will still generate self-signed certificate for the chosen IP address, and everything will still work seamlessly.

#### User Name and Password
The script also asks for username and password to create the first local account. This set of credentials can be used to login to web library as well as desktop clients to sync with this server.

## Web Library
Simply navigate to the Web Library link shown at the end of the installation and login with the username and password you provided during installation.

Unlike previous selfhosting attempts mentioned in the credits section below, this script creates apache configuration to provide access to all services via a single endpoint. This makes it easy to host this server behind a reverse proxy, since only a single entry needs to be created in reverse proxy to point to the single endpoint that this installation provides.

Simply point your reverse proxy to `http://ip.addr.of.server:80` and that's it. All the web library, api, file attachments, websockets, minio traffic will go through this one endpoint.

Assuming you choose `zotero.your-domain.xyz` as your domain name, you can reach the following services at the URLs provided.

| Service              | URL                                    |
|----------------------|----------------------------------------|
| Web Library          | https://zotero.your-domain.xyz/        |
| API                  | https://zotero.your-domain.xyz/api/    |
| Attachment Proxy     | https://zotero.your-domain.xyz/fs/    |
| Web Sockets          | wss://zotero.your-domain.xyz/ws/       |
| MinIO UI             | https://zotero.your-domain.xyz/minio/  |
| MinIO Web Sockets    | wss://zotero.your-domain.xyz/minio/ws/ |

## Desktop Clients
There is no need to rebuild desktop clients as mentioned by [ilyasoloma@zotero-forums](https://forums.zotero.org/discussion/114399/self-hosted-zotero-how-to-make-windows-client-use-it). This script generates two additional scripts to automate patching of official desktop clients. These scripts are placed in `/opt/zotero/scripts` directory after successful install.

### Ubuntu / Debian
Install Zotero Desktop Client either the [official way](https://www.zotero.org/support/installation), or via `apt` using this repository: https://github.com/retorquere/zotero-deb

Then copy the script **/opt/zotero/scripts/patch_zotero_desktop.sh** to your desktop computer and execute it with sudo to patch the official client.

```
chmod +x patch_zotero_desktop.sh

sudo ./patch_zotero_desktop.sh
```

### Windows
Download the Zotero Desktop Client from official [website](https://www.zotero.org/download/) and install as you would install any other software.

Windows PowerShell prevents execution of scripts by default. Launch PowerShell with Elevated (admin) privileges, and run this command before running the script to allow scripts execution for current session.


```
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

Copy the generated script **/opt/zotero/scripts/patch_zotero_desktop.ps1** to your Windows computer and execute it to patch Zotero Desktop Client.

```
.\patch_zotero_desktop.ps1
```

### Desktop Clients Backup

Both Linux and Windows scripts create backup of the `omni.ja` file as `omni.ja.bak` in the respective installation directories, so if something goes wrong during patchwork, you should be able to manually rescue your clients.

## Credits
Putting together this script would not have been possible without learning from all the past attempts at selfhosting zotero, so a big shoutout to all those people who paved the way.

1. https://github.com/linuxrrze/dockerized-zotero
2. https://github.com/uniuuu/zotprime
3. https://github.com/ilyasoloma/zotero-selfhost
3. [ilyasoloma@zotero-forums](https://forums.zotero.org/discussion/114399/self-hosted-zotero-how-to-make-windows-client-use-it) - for advising to patch official desktop clients instead of rebuilding.

