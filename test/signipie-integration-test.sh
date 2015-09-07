#!/bin/bash

export PYTHONPATH=.
export PATH=bin:$PATH
HOMEDIR=$(mktemp -d)
PLAYDIR=$(mktemp -d)

echo $HOMEDIR
echo $PLAYDIR

# generate
signipie --home "$HOMEDIR" -i id_alice generate -n
echo $?
signipie --home "$HOMEDIR" -i id_bob generate -n
echo $?
signipie --home "$HOMEDIR" -i id_mallory generate -n
echo $?
mkdir "$HOMEDIR/trusted"
cp "$HOMEDIR/id_alice.pub" "$HOMEDIR/trusted"
cp "$HOMEDIR/id_bob.pub" "$HOMEDIR/trusted"

# files for signing and stuff
echo 'My simple message to sign' > "$PLAYDIR/simple"
echo 'A little file 1' > "$PLAYDIR/file1"
echo 'A little file 2' > "$PLAYDIR/file2"
echo 'A little file 3' > "$PLAYDIR/file3"

# sign and verify
echo "SIMPLE SIGNATURE"
echo "----------------"
signipie --home "$HOMEDIR" -i id_alice sign "$PLAYDIR/simple"
echo $?
cat "$PLAYDIR/simple.sig"
signify -S -x "$PLAYDIR/simple.sig-ref" -s "$HOMEDIR/id_alice" -m "$PLAYDIR/simple"
cat "$PLAYDIR/simple.sig-ref"

signipie --home "$HOMEDIR" verify -x "$PLAYDIR/simple.sig" "$PLAYDIR/simple"
echo $?
echo
echo "EMBEDDED SIGNATURE"
echo "------------------"
signipie --home "$HOMEDIR" -i id_alice sign -e "$PLAYDIR/simple" -o "$PLAYDIR/simple.embedded"
echo $?
cat "$PLAYDIR/simple.embedded"
signify -S -e -x "$PLAYDIR/simple.embedded-ref" -s "$HOMEDIR/id_alice" -m "$PLAYDIR/simple"
cat "$PLAYDIR/simple.embedded-ref"

signipie --home "$HOMEDIR" verify -e "$PLAYDIR/simple.embedded"
echo $?
echo
echo "CHECKSUM SIGNATURES"
echo "-------------------"
signipie --home "$HOMEDIR" -i id_alice sign -c -o "$PLAYDIR/simple.checksum" "$PLAYDIR/file1" "$PLAYDIR/file2" "$PLAYDIR/file3"
echo $?
cat "$PLAYDIR/simple.checksum"
sha256sum --tag "$PLAYDIR/file1" "$PLAYDIR/file2" "$PLAYDIR/file3" > "$PLAYDIR/fileN.hashes"
signify -S -e -x "$PLAYDIR/simple.checksum-ref" -s "$HOMEDIR/id_alice" -m "$PLAYDIR/fileN.hashes"
cat "$PLAYDIR/simple.checksum-ref"

signipie --home "$HOMEDIR" verify -c -x "$PLAYDIR/simple.checksum"
echo $?
echo
echo "TEST FAILURES"
echo "-------------"

signipie --home "$HOMEDIR" -p "$HOMEDIR/id_bob.pub" verify -x "$PLAYDIR/simple.sig" "$PLAYDIR/simple"
echo $?
signipie --home "$HOMEDIR" -p "$HOMEDIR/id_bob.pub" verify -e "$PLAYDIR/simple.embedded"
echo $?
signipie --home "$HOMEDIR" -p "$HOMEDIR/id_bob.pub" verify -c -x "$PLAYDIR/simple.checksum"
echo $?

echo "broken" >> "$PLAYDIR/file2"
rm "$PLAYDIR/file3"
signipie --home "$HOMEDIR" verify -c -x "$PLAYDIR/simple.checksum"
echo $?
signify -C -p "$HOMEDIR/id_alice.pub" -x "$PLAYDIR/simple.checksum"


# Cleanup
rm -r "$HOMEDIR"
rm -r "$PLAYDIR"
