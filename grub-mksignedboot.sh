#!/bin/bash

# grub-mksignedboot.sh

# https://www.gnu.org/software/grub/manual/grub/grub.html#Security

# What this does:
# Creates and embeds a GPG key into a custom GRUB efi binary to enforce signature checking of GRUB components under /boot

# What this is for:
# If Measured Boot, vboot, or SecureBoot is not an option for your system, this is one link in a secure booting chain that can be implemented.

# What this does not do:
# Currently there's no built in way to automatically run this script if a boot component is updated. You need to do this manually.
# This script does not configure an admin account to password protect GRUB, you will need to do that as well
# None of this protects the device's firmware, for that you need a power-on password or one of the above boot security implementations.

# Thanks to the following projects for code, ideas, and guidance:
# https://github.com/g0tmi1k/OS-Scripts
# https://github.com/angristan/wireguard-install
# https://github.com/drduh/YubiKey-Guide
# https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-stig.html
# https://github.com/ComplianceAsCode/content

BLUE="\033[01;34m"   # information
GREEN="\033[01;32m"  # information
YELLOW="\033[01;33m" # information
RED="\033[01;31m"    # errors
BOLD="\033[01;01m"   # highlight
RESET="\033[00m"     # reset

# This may only work on ubuntu, will need tested on other distros
OS_ID="$(grep -P "^ID=" /etc/os-release | cut -d '=' -f 2)"

# Generates a single random passprhase if the signing 
# key does not exist, stores it in this variable
# https://github.com/drduh/YubiKey-Guide#master-key
PASSPHRASE="$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"

# Must be run as root
if ! [[ "$EUID" == 0 ]]; then
	echo -e "This script must be run as root."
	exit 1
fi

# Warning for automatic updates
echo -e "${RED}[i]WARNING${RESET}"
echo -e "When a boot component is updated this script does not automatically run."
echo -e "You must run this script to sign all boot components after updates, before powering off the system."
echo ''
until [[ $WARNING_OK =~ ^(y|n)$ ]]; do
	read -rp "Continue? [y/n]: " -e -i n WARNING_OK
done
if [ "$WARNING_OK" == 'n' ]; then
	exit
fi

# Check for a GRUB signing key in /root/.gnupg
if ! (gpg --list-keys 2>/dev/null | grep -q 'grub-signing-key'); then

	# https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
	# https://www.gnu.org/licenses/gpl-3.0.en.html

	echo -e "[${BLUE}>${RESET}]Writing heredoc to ${YELLOW}/root/grub-gpg-params${RESET}..."

	# Modify parameters here as needed
	cat >/root/grub-gpg-params <<EOF
	Key-Type: default
	Subkey-Type: default
	Name-Real: grub-signing-key
	Expire-Date: 0
	Passphrase: $PASSPHRASE
	%commit
EOF

	echo -e "[${BLUE}>${RESET}]Generating a GPG key for signing GRUB components..."
	gpg --batch --generate-key /root/grub-gpg-params > /dev/null
	
	# Export public key
	echo -e "[${BLUE}>${RESET}]Exporting public key to ${YELLOW}/boot/grub/grub.pub${RESET}..."
	gpg --export 'grub-signing-key' > /boot/grub/grub.pub
else
	echo -e "[${BLUE}i${RESET}]GRUB signing key found."

	# Check / prompt for the passphrase to unlock the signing key during batch processing
	# This could be improved to create the file interactively if it's missing
	if ! [[ -e /root/grub-gpg-params ]]; then
		echo -e "[i]/root/grub-gpg-params not found."
		echo -e "Create this file with the single line of 'Passphrase: <past-passphrase-here>'"
		echo ""
		echo -e "This is enough for batch processing."
		echo -e "Be sure you save the passphrase to a credential vault before deleting the file."

		exit 1
	fi
	
	# Check if a custom image is already built, and ask to install it
	if [[ -e /boot/efi/EFI/"$OS_ID"/grub_customx64.efi ]]; then
		echo ""
		echo -e "Do you want to install ${YELLOW}grub_customx64.efi${RESET}?"
		echo -e "${BOLD}Only do this if you've confirmed it's working${RESET}."
		echo ""
		until [[ $INSTALL_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "Selection [y/n]: " -e -i n INSTALL_CHOICE
		done
		if [ "$INSTALL_CHOICE" == 'n' ]; then
			echo ""
			echo "Update signatures?"
			echo "This will generate a new efi binary and signatures for all GRUB components."
			echo ""
			until [[ $UPDATE_CHOICE =~ ^(y|n)$ ]]; do
				read -rp "Selection [y/n]: " -e -i n UPDATE_CHOICE
			done
			if [ "$UPDATE_CHOICE" == 'y' ]; then
				return 1
			else
				exit 0
			fi
		elif [ "$INSTALL_CHOICE" == 'y' ]; then
			# Use -n to prevent copy operation from overwriting the original GRUB efi binary with a custom one installed later
			cp -n /boot/efi/EFI/"$OS_ID"/grubx64.efi /boot/efi/EFI/"$OS_ID"/grubx64.bkup.efi
			mv /boot/efi/EFI/"$OS_ID"/grub_customx64.efi /boot/efi/EFI/"$OS_ID"/grubx64.efi
			echo -e "[${GREEN}✓${RESET}]Custom GRUB image installed."
			exit 0
		fi
	fi
fi

# Set GRUB to show a countdown after boot to enter the GRUB menu
if ! (grep -Pqx "^GRUB_TIMEOUT=3$" /etc/default/grub); then
	sed -i 's/^GRUB_TIMEOUT=0$/GRUB_TIMEOUT=3/' /etc/default/grub
	echo -e "[${BLUE}>${RESET}]Setting ${BOLD}GRUB_TIMEOUT=3${RESET}..."
fi
if ! (grep -Pqx "^GRUB_TIMEOUT_STYLE=countdown$" /etc/default/grub); then
	sed -i 's/^GRUB_TIMEOUT_STYLE=hidden$/GRUB_TIMEOUT_STYLE=countdown/' /etc/default/grub
	echo -e "[${BLUE}>${RESET}]Setting ${BOLD}GRUB_TIMEOUT_STYLE=countdown${RESET}..."
fi

# Ensure all changes are loaded into GRUB and it's config file
# This should be the last thing you do before signing all of the GRUB components
echo -e "[${BLUE}>${RESET}]Updating GRUB components..."
if ! (update-grub); then
	# Exit if there's invalid syntax in grub.cfg or other errors
	echo -e "[${RED}i${RESET}]Error with grub configuration. Quitting."
	exit 1
fi

# Generate the custom GRUB efi binary
# This should always be done when updating the GRUB components, kernel, or signatures
# This ensures any updates to GRUB are embedded within the latest efi binary
echo -e "[${BLUE}>${RESET}]Running grub-mkstandalone..."
if ! (grub-mkstandalone --format=x86_64-efi --output=/boot/efi/EFI/"$OS_ID"/grub_customx64.efi --pubkey=/boot/grub/grub.pub --modules="verifiers gcry_sha256 gcry_sha512 gcry_dsa gcry_rsa" /boot/grub/grub.cfg=/boot/grub/grub.cfg); then
	echo -e "[${RED}i${RESET}]Error compiling custom GRUB image. Quitting."
	exit 1
else
	echo -e "[${GREEN}✓${RESET}]Custom GRUB efi binary written to: ${YELLOW}/boot/efi/EFI/$OS_ID/grub_customx64.efi${RESET}"
fi

# Write passphrase into memory for --batch processing
if [[ -e /root/grub-gpg-params ]]; then
	echo -e "[${BLUE}i${RESET}]Writing phassphrase to ${YELLOW}/dev/shm/passphrase.txt${RESET}..."
	grep -F 'Passphrase: ' /root/grub-gpg-params | awk '{print $2}' | tee /dev/shm/passphrase.txt > /dev/null
fi

# Remove old signatures when updating
if (find /boot -type f -name "*.sig" -print0 | xargs -0 sudo rm 2>/dev/null); then
	echo -e "[${BLUE}i${RESET}]Removing previous signatures..."
fi

# Generate new signatures
# https://github.com/koalaman/shellcheck/wiki/SC2044
# This for loop is adapted directly from the GRUB manual:
# https://www.gnu.org/software/grub/manual/grub/grub.html#Using-digital-signatures
for i in $(find /boot -type f -name "*.cfg" -or -name "*.lst" -or -name "*.mod" -or -name "vmlinuz*" -or -name "initrd*" -or -name "grubenv"); do
	if ! [[ -e "$i".sig ]]; then
		if ! (gpg --batch --detach-sign --pinentry-mode loopback --passphrase-fd 0 "$i" < /dev/shm/passphrase.txt); then
			echo -e "[${RED}i${RESET}]Error signing $i. Review ${YELLOW}/dev/shm/passphrase.txt${RESET}. Quitting."
			exit 1
		else
			echo -e "[${GREEN}>${RESET}]Signing $i..."
		fi
	fi
done

echo -e "[${BLUE}>${RESET}]Shredding plaintext key in memory..."
shred -n 7 -v /dev/shm/passphrase.txt

echo '============================================================'
echo -e "[${GREEN}i${RESET}]GPG Key Passphrase: $PASSPHRASE"
echo ""
echo -e "[${GREEN}i${RESET}]GPG Key Fingerprint:"
gpg --list-key --with-fingerprint grub-signing-key
echo ""

echo -e "[${GREEN}i${RESET}]Your passphrase is written to ${YELLOW}/root/grub-gpg-params${RESET}."
echo -e "${BOLD}Save that passphrase to your credential vault before deleting this file${RESET}."
echo -e "Once you've saved your passphrase this file can be deleted."
echo '============================================================'
echo -e "[${BLUE}>${RESET}]Next: ${YELLOW}reboot${RESET} into your system's EFI shell, and launch ${YELLOW}grub_customx64.efi${RESET}."
echo ""
echo -e "Run ${YELLOW}list_trusted${RESET} from the GRUB shell to ensure your public key is present."
echo ""
echo -e "If you can boot successfully, run this script again to install the new GRUB efi binary."
echo -e "The original binary will be safely backed up to ${YELLOW}/boot/efi/EFI/$OS_ID/grubx64.bkup.efi${RESET}."
echo ""
echo -e "If your firmware does not have a built in EFI shell you will need to follow the"
echo -e "Chipsec documentation to write one to a USB drive."
echo ""
echo -e "[${YELLOW}i${RESET}]Steps:"
echo -e "    ${BLUE}https://chipsec.github.io/installation/USB%20with%20UEFI%20Shell.html${RESET}"
echo ""
echo -e "[${YELLOW}i${RESET}]EFI Shell Binary:"
echo -e "    ${BLUE}https://github.com/tianocore/edk2/blob/UDK2018/ShellBinPkg/UefiShell/X64/Shell.efi${RESET}"
echo '============================================================'
echo -e "[${GREEN}✓${RESET}]Done."
