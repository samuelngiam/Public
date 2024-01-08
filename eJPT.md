- [SECTION 3 Host and Network Penetration Testing](#SECTION-3-Host-and-Network-Penetration-Testing)
  - System and Host Based Attacks
  - Network-Based Attacks
  - The Metasploit Framework (MSF)
  - Exploitation
  - Post-Exploitation
  - Social Engineering

# SECTION 3 Host and Network Penetration Testing

## System and Host Based Attacks

## Network-Based Attacks

## The Metasploit Framework (MSF)

## Exploitation
### AV Evasion & Obfuscation
- https://www.shellterproject.com/

```
sudo apt install shellter -y
```
- Shellter is a Windows executable, need Wine (https://www.winehq.org/) which is a compatibility layer for running Windows software on Unix-like systems.

```
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install wine32 -y
```

```
mkdir ~/Desktop/AVBypass
cp /usr/share/windows-resources/binaries/vncviewer.exe ~/Desktop/AVBypass/vncviewer.exe

cd /usr/share/windows-resources/shellter
sudo wine shellter.exe
```
- After execution, a backup of the original PE is stored in `/usr/share/windows-resources/shellter/Shellter_Backups`.
- Select Stealth mode - `vncviewer.exe` will function normally.

## Post-Exploitation

## Social Engineering
