# SolGB

Game Boy cold storage wallet. The minigame is PUMP IT.

Spending is handled by [signgb.app](https://signgb.app), a separate multi-coin signer. The copy under `docs/` is kept here for reference and for self use.

## Features

- Generate BIP39 mnemonic phrases
- Create a Solana address (m/44'/501'/0'/0')
- QR Address Display
- Built-in entropy generation via PUMP IT
- Optional 6-Button PIN
- Duress Silent Delete Code (PIN Backwards)
- Encrypted Save Data
- ROM Integrity Verification
- Runtime Automated Test Suite


## Security Considerations

This is built to be used on **Air-Gapped Devices** only, meaning no internet. 

Before using to store crypto it is recommended to run the built-in test suite to verify the platform.

Sensitive save data is encrypted using the PIN but it is only meant to keep out the overly curious and novice attackers.
 
Deleting data may not prevent forensic recovery (flash cartridges are a black box).

On certain emulators it may automatically increase Minigame play time to account for low input resolution.



### Healthy Practices

Treat this like a paper wallet.

That means:

- Keep it physically secure
- Keep cameras away from sensitive information
- For flash cartridges, use a dedicated SD Card that never gets plugged into a computer again!


## Building

Requirements:
- GCC, Make
- Python3 (pip: mnemonic, base58, pynacl)
- GBDK (Game Boy Development Kit):
    - Download from: [https://gbdk-2020.github.io/gbdk-binaries/](https://github.com/gbdk-2020/gbdk-2020)
    - Extract to project root as `gbdk/` folder

To build `SolGB.gb`
```bash
make
```

## Building on WSL (Windows)

Install WSL: 
```bash
wsl --install Debian
```

In project directory with linux gbdk:
```bash
sudo apt-get update
sudo apt-get install python3 python3-mnemonic python3-base58 python3-nacl gcc make
make
```


## Unique Build-Time Entropy

If you are concerned about runtime entropy generation being insufficient, you can add build-time entropy yourself by running:

```bash
make entropy && make
```


## Testing

You can run crypto validation tests against python3's implimentation by running:

```bash
make test
```

To test ROM integrity checks, you can corrupt a ROM (flip a random bit) by running:

```bash
python3 tools/corrupt_rom.py ./build/SolGB.gb
```



*Disclaimer: SolGB is an independent, open-source project made using GBDK and is not affiliated with, endorsed by, or licensed by Nintendo. No Nintendo assets were used in its creation. "Game Boy" and "Game Boy Color" are registered trademarks of Nintendo. All trademarks are the property of their respective owners.*
