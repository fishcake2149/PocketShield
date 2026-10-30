# PocketShield 0.1 (experimental)

Android 8+ Kotlin app that uses Android VpnService to route IPv4 UDP DNS queries through a local DNS filter. It forwards allowed queries to Cloudflare 1.1.1.1 and returns NXDOMAIN for blocked domains.

## First use
1. Download the APK from the GitHub Actions build artifact.
2. Install it, open PocketShield, and tap **필터 업데이트** before enabling filtering. Without this step, the blocklist is empty.
3. Tap **광고 차단 켜기** and accept the Android VPN permission.
4. Confirm websites still load and the counter changes when blocked DNS queries occur.
5. Tap **광고 차단 끄기** if network connectivity is affected.

## Build on a phone
Open Actions > Android APK > latest successful run > Artifacts > PocketShield-debug-apk.
The build uses Gradle 8.9, Android Gradle Plugin 8.7.3, Kotlin 2.0.21, Java 17, SDK 35.

## Limitations
- This is a prototype, not yet verified on a real Android device. No guarantee that DNS filtering will work on every phone.
- Only IPv4 UDP DNS routed through the virtual DNS is handled; TCP DNS, IPv6, encrypted DNS, app-specific DNS, and cosmetic popup removal are not supported.
- Private DNS may bypass the filter. Android supports only one active VPN at a time.
- Normal DNS requests are forwarded to Cloudflare. The developer does not operate a remote server.
- The StevenBlack hosts list is downloaded over HTTPS, but there is no checksum/signature pinning.
- Do not rely on this app for network security or privacy protection.
