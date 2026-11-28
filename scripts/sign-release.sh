#!/bin/sh
# Sign a published release: scripts/sign-release.sh v0.2.10
# Downloads SHA256SUMS of the release, signs it with the release key held by the SSH agent
# (the private half never leaves the password manager) and leaves SHA256SUMS.sig to upload.
# The public half is packaging/release-key.pub and the `signer` line in site/install.sh.
set -eu
tag=${1:?usage: scripts/sign-release.sh vX.Y.Z}
repo=onokashino/keywarden
root=$(cd "$(dirname "$0")/.." && pwd)
pub=$root/packaging/release-key.pub
[ -s "$pub" ] || { echo "no release key yet: put the public key into packaging/release-key.pub" >&2; exit 1; }
key=$(awk '{ print $1 " " $2 }' "$pub")
grep -qF "signer='$key'" "$root/site/install.sh" || { echo "site/install.sh has a different signer than packaging/release-key.pub" >&2; exit 1; }
ssh-add -L 2>/dev/null | grep -qF "$key" || { echo "the release key is not in the SSH agent; unlock Keywarden and run: eval \"\$(kw ssh-env)\"" >&2; exit 1; }

out=$root/target/release-sign/$tag
mkdir -p "$out"
curl --proto '=https' --tlsv1.2 -fsSL -o "$out/SHA256SUMS" "https://github.com/$repo/releases/download/$tag/SHA256SUMS"
rm -f "$out/SHA256SUMS.sig"
ssh-keygen -Y sign -U -f "$pub" -n keywarden-release "$out/SHA256SUMS"
printf 'release@keywarden %s\n' "$key" > "$out/signers"
ssh-keygen -Y verify -f "$out/signers" -I release@keywarden -n keywarden-release -s "$out/SHA256SUMS.sig" < "$out/SHA256SUMS"
echo
echo "signed: $out/SHA256SUMS.sig"
echo "upload it to the release: https://github.com/$repo/releases/edit/$tag"
