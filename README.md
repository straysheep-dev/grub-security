# GRUB Security

Security configurations for GRUB, a common Linux bootloader.

The steps to enable signature checking do not appear to be fully documented in GRUB's manual (at least as far as what's required in recent Ubuntu desktop releases), which is why this repository and the tool [grub-mksignedboot.sh](/grub-mksignedboot.sh) were created. This tool will do everything outlined in this README automatically, and can be run again to update signatures.

- [GRUB Security Manual](https://www.gnu.org/software/grub/manual/grub/grub.html#Security)

This README covers two main points:

- Enforce signature checking in GRUB of the critical `/boot` components
- Password protect the GRUB menu

In both cases this does not prevent tampering, the goal is to detect it.

Signing all of the /boot files means any modifications to them will *prevent the system from booting*. This should serve as a warning to repeat and be familiar with these steps in a virtual machine or a test system before using them on production machines.

Password protecting both the UEFI/BIOS menu, and the GRUB menu requires a (non-targeted) attacker to open the case of the device, and remove your internal drives (mounting them directly to a system of their own) to modify the boot partitions. *This can be detected by embedded UEFI/BIOS tamper protection mechanisms included by OEM's like Dell, or by sealing the screws on your case with paint or nail polish which won't prevent access but clearly shows if the case was opened.* Thanks to [Johannes Ullrich and the daily Stormcast](https://isc.sans.edu/podcast.html) as well as [Jim Ducroiset from Active Countermeasuers](https://www.youtube.com/watch?v=8izmlbFkBo4) for sharing the tip on using paint or nail polish!

This is an ideal situation. In less than ideal situations bypasses exist in less secure firmware which can allow attackers with physical access to enter the firmware's menu by connecting over external ports and sending a payload.

Ultimately this is meant to prevent non-targeted attacks where the adversary has physical access, from trivially backdooring your boot partition.

#### IMPORTANT:

This does *NOT* prevent attackers with physical access from modifying your firmware, use a firmware password, TPM measurements, Measured Boot / vboot, or SecureBoot for this. Firmware is *below* the boot loader and the operating system.

For additional technical resources on firmware, boot, and lower level security, [Paul Asadoorian](https://twitter.com/securityweekly)'s 3 part series on these topics is a great quick-start with examples:

- [firmware-security-realizations-part-1-secure-boot-and-dbx](https://eclypsium.com/2022/07/26/firmware-security-realizations-part-1-secure-boot-and-dbx/)
- [firmware-security-realizations-part-2-start-your-management-engine](https://eclypsium.com/2022/08/10/firmware-security-realizations-part-2-start-your-management-engine/)
- [firmware-security-realizations-part-3-spi-write-protections](https://eclypsium.com/2022/09/19/firmware-security-realizations-part-3-spi-write-protections/)

## Grub Security Overview

- Create a GPG signing key just for GRUB files and `/boot` components
- Save a *non-ascii* export of the public key to `/boot/grub/grub.pub`
- Use `grub-mkstandalone` to compile a custom grub efi binary with signature checking modules and our public key embedded
- Save this binary next to the current one, as `/boot/efi/EFI/ubuntu/grub_customx64.efi`
- Sign all of the GRUB / boot components with the GPG key
- Password protect the GRUB menu, create a single administrative user
- Repeat the steps above to update GRUB and embed the admin user into the GRUB efi binary

--- 

## Generate a GPG signing key

Most if not all of these operations will require root. We'll use the /root directory and root's GPG keyring, so only root has access.

Create the key.

- Enter grub-signing-key as the name
- Leave email blank
- For manually testing, use a simple password like 123456

```bash
sudo gpg --gen-key
```

Keep in mind root does not have the same `gpg.conf` as you, and for signing GRUB and boot components, it's less important but worth considering if you need to make changes there.

Next we'll need to export the public key. This *MUST* be in a binary format (not `--armor`'d output) or GRUB will not be able to read it.

```bash
sudo gpg --export '$KEYID' > /boot/grub/grub.pub
```

`/boot/grub/grub.pub` was chosen because it's within the `/boot` partition, making it available to read if needed for recovery. Otherwise this key can be read from anywhere by `grub-mkstandalone` to embed it at compile time.

## Configure GRUB for testing

So you can easily boot into a GRUB shell and review changes on the next reboot:

```bash
sudo sed -i 's/^GRUB_TIMEOUT=0$/#GRUB_TIMEOUT=0/' /etc/default/grub
sudo sed -i 's/^GRUB_TIMEOUT_STYLE=*$/GRUB_TIMEOUT_STYLE=countdown/' /etc/default/grub
```

You won't need to make any additional modifications to grub config files for signature verification. From the [grub manual](https://www.gnu.org/software/grub/manual/grub/grub.html#Using-digital-signatures):

> ...Passing one or more `--pubkey` options to `grub-mkimage` implicitly defines `check_signatures` equal to `enforce` in core.img prior to processing any configuration files.

We never need to run `grub-mkimage` directly, as it's run as part of `grub-mkstandalone`.

## The grubx64.efi binary

This seems to be required to 'preload' the signature verification modules in GRUB to successfully perform signature validation.

- Simply running `sudo grub-install /dev/sda --pubkey /boot/grub/grub.pub` does not enforce signature checking.
- Even running `sudo grub-mkimage ...` and replacing the `core.efi` binary under `/boot/grub/x86_64-efi/` does not enforce signature checking.

You can verify this from a grub shell after trying the above steps for yourself by running:

```grub
list_trusted
```

If you don't receive any output, the public key is not loaded or embedded in the current `grubx64.efi` image.

What we need to use is `grub-mkstandalone`.

- We need to replace `/boot/efi/EFI/ubuntu/grubx64.efi` with our custom image that verifies signatures and knows our public key
- During testing we'll write the custom image to `/boot/efi/EFI/ubuntu/grub_customx64.efi` so the original efi binary is still the default image to boot from
- We'll attempt to boot the custom image from an EFI shell and address or note any issues from there

**NOTE**: *The path `/boot/efi/EFI/ubuntu/` is used as this is the path on both 20.04 and 22.04. This path may change depending on the OS you're using.*

An easy way to test GRUB efi binaries is using a virtualization platform like VMware:

- Poweroff
- VMware > VM > Power > Power On to Firmware
- EFI Internal Shell
- Press any key to continue (before the countdown ends)
- Start below by typing `fs0:` and hitting enter, to enter the fs0 filesystem

```efi
fs0:
fs0:\> ls # just to show you can list contents of the .\EFI directory and more
fs0:\> .\EFI\ubuntu\grub_customx64.efi
```

---

## Compiling a custom GRUB efi binary

The `grub-mkstandalone` command is never mentioned in the [GRUB manual](https://www.gnu.org/software/grub/manual/grub/grub.html), but is required (at least on Ubuntu) to successfuly enable and deploy the signature checking mechanism GRUB offers.

Thanks to this question posted by user Daniel, and answer provided by user Fonic. The `grub-mkstandalone` command here was adapted directly from the examples in that post.

- <https://unix.stackexchange.com/questions/531992/enabling-check-signatures-in-grub>

**IMPORTANT**: Check which version of GRUB you have installed, as of 2.06 the `verifiers` module may no longer need preloaded (This could vary by system and needs tested).

```bash
grub-install --version
```

This is the command to create a new grub x86_64 efi binary:

```bash
# Always update-grub first, in case there have been any changes
sudo update-grub

sudo grub-mkstandalone --verbose --format=x86_64-efi --output=/boot/efi/EFI/ubuntu/grub_customx64.efi --pubkey=/boot/grub/grub.pub --modules="verifiers gcry_sha256 gcry_sha512 gcry_dsa gcry_rsa" /boot/grub/grub.cfg=/boot/grub/grub.cfg
```

Because of `--verbose` if we scroll up far enough in the ouput, the `grub-mkimage` command that was run automatically is shown:

> ```
> grub-mkimage --directory '/usr/lib/grub/x86_64-efi' --prefix '(memdisk)/boot/grub' --output '/boot/efi/EFI/ubuntu/grub_customx64.efi'  --dtb '' --format 'x86_64-efi' --compression 'auto'  --memdisk '/tmp/grub.fOZvyK' --pubkey '/boot/grub/grub.pub' 'verifiers' 'gcry_sha256' 'gcry_sha512' 'gcry_dsa' 'gcry_rsa' 'memdisk' 'tar'
> ```

After the command exits, the new efi binary will be under `/boot/efi/EFI/ubuntu/grub_customx64.efi`

---

## Signing boot files

*This should always be the last step, once the GRUB binary has the public key and latst config file embedded you can sign everything to be sure all GRUB components will load*

- [GRUB - Using digital signatures](https://www.gnu.org/software/grub/manual/grub/grub.html#Using-digital-signatures)

Programmatically sign all boot files. The [online manual for GRUB](https://www.gnu.org/software/grub/manual/grub/grub.html#Using-digital-signatures) provides a script you can use to do this. The example below is a modified version of that script:

```bash
#!/bin/bash

# Must be run as root
if ! [[ "$EUID" == 0 ]]; then
	echo -e "This script must be run as root."
	exit 1
fi

# Ensure all changes made to GRUB's configuration are loaded
# This should be the last thing you do before signing all boot files
update-grub

# Compile the custom GRUB efi binary
grub-mkstandalone --verbose --format=x86_64-efi --output=/boot/efi/EFI/ubuntu/grub_customx64.efi --pubkey=/boot/grub/grub.pub --modules="verifiers gcry_sha256 gcry_sha512 gcry_dsa gcry_rsa" /boot/grub/grub.cfg=/boot/grub/grub.cfg

# This line is just for running tests
#echo '123456' > /dev/shm/passphrase.txt

# Write the GPG key's passphrase to memory for batch processing
if ! [ -e /dev/shm/passphrase.txt ]; then
	echo "Paste your grub signing key passphrase into /dev/shm/passphrase.txt"
	exit 1
fi

# Remove old signatures when updating
if (find /boot -type f -name "*.sig" -print0 | xargs -0 rm 2>/dev/null); then
	echo "Removing previous signatures..."
fi

# Sign all of the GRUB / boot components
for i in $(find /boot -type f -name "*.cfg" -or -name "*.lst" -or -name "*.mod" -or -name "vmlinuz*" -or -name "initrd*" -or -name "grubenv"); do
	if ! [ -e "$i".sig ]; then
		echo "Signing $i..."
		gpg --batch --detach-sign --pinentry-mode loopback --passphrase-fd 0 "$i" < /dev/shm/passphrase.txt
	fi
done

echo "[>]Shredding plaintext key in memory..."
shred -n 7 -v /dev/shm/passphrase.txt
```

**WARNING**: Anytime you change or update GRUB, it's config, the kernel, or any other boot components, you need to recompile the custom GRUB binary and write new signatures for all the boot files.

Once the script is finished you can reboot / poweroff and continue to the next section.

# Testing Signature Enforcement

A quick recap of what we've done up to now:

- Create a GPG signing key just for GRUB files and `/boot` components
- Save a *non-ascii* export of the public key to `/boot/grub/grub.pub`
- Use `grub-mkstandalone` to compile a custom grub efi binary with signature checking modules and our public key embedded
- Save this binary next to the current one, as `/boot/efi/EFI/ubuntu/grub_customx64.efi`
- Sign all of the GRUB / boot components with the GPG key

Because we still have the original `grubx64.efi` binary in place, we can safely run the following command:

```bash
sudo rm /boot/efi/EFI/ubuntu/*.sig
```

This will delete all of the detached signature files in that directory.

Go through the steps once more of booting into the EFI shell and loading our custom GRUB binary:

```efi
fs0:
fs0:\> EFI/ubuntu/grub_customx64.efi
```

You should see GRUB complain that a `.sig` file was not found. Just one failed signature is enough to prevent GRUB from booting into the OS.

To correct this, reboot so the original `grubx64.efi` binary (which is still the default) loads, and sign all of the GRUB components.

# Deployment

Run the following to 'install' the custom GRUB binary, and keep a backup of the original:

```bash
sudo cp -n /boot/efi/EFI/ubuntu/grubx64.efi /boot/efi/EFI/ubuntu/grubx64.bkup.efi
sudo mv /boot/efi/EFI/ubuntu/grub_customx64.efi /boot/efi/EFI/ubuntu/grubx64.efi
```

This is a good way to test this on a small set of systems.

- The GRUB menu is (or will be in the next section) password protected
- If something goes wrong, boot into an EFI shell and execute the previous image: `grubx64.bkup.efi`

# Password protecting GRUB

[GRUB - Authentication and authorisation](https://www.gnu.org/software/grub/manual/grub/grub.html#Authentication-and-authorisation)

This is done last so you aren't stuck entering a GRUB password while testing and configuring signature verification in the GRUB menu.

Generate a hash of your password:

```bash
grub-mkpasswd-pbkdf2
```

It's the entire string, starting with `grub.pbkdf2.sha512.10000...`, which we'll need to highlight and copy.

### Add a user and password to /etc/grub.d/40_custom

This creates a single administrative user and password protects all GRUB menu entries.

Enter the following lines (with your own password hash) below the comments at the top of `/etc/grub.d/40_custom`:

```
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.10000.4DC37841103E9C41817DB083383337...
}
```

This will require a password to move past the GRUB menu, meaning even just to boot into the OS. This can be improved by allowing anyone to boot into the installed OS, but only the local administrator can modify GRUB or access the other menu items such as the firmware menu.

Finally, after adding your administrative user to`/etc/grub.d/40_custom`, you'll need to update GRUB and compile this new configuration into the custom efi binary:

- `sudo update-grub`
- `sudo grub-mkstandalone --format=x86_64-efi --output=/boot/efi/EFI/ubuntu/grub_customx64.efi --pubkey=/boot/grub/grub.pub --modules="verifiers gcry_sha256 gcry_sha512 gcry_dsa gcry_rsa" /boot/grub/grub.cfg=/boot/grub/grub.cfg`
- Sign all of the GRUB components again

On the next boot you'll be taken to the GRUB menu and asked for a password before taking any action.

