# authenticator
An OTP (one-time-password) app for desktop use!

Familiar with Google/Microsoft Authenticator, apps where you scan a QR code and get a 6 digit pin that refreshes every 30 seconds?  
This uses a standardised protocol - one that is implemented in this desktop app.

# Features

- 🚀🚀🚀 BLAZINGLY FAST AND MEMORY SECURE
- Encrypted secrets

# Building

`cargo build --release`

## Cross compilation

Works with rust's built-in cross compilation features:

`cargo build --target x86_64-pc-windows-gnu --release`

You may have to install new targets as such:  
`rustup target add x86_64-pc-windows-gnu`

# To Do

- UI Improvements
  - Multiple profiles
  - Anything else
- QR code scanning
