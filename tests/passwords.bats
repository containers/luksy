#!/usr/bin/env bats

lukstool=${LUKSTOOL:-${BATS_TEST_DIRNAME}/../lukstool}

@test passwords-cryptsetup-defaults {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        for luksVersion in "luks2" "luks1" ; do
            echo password: "${password}"
            echo version: "${luksVersion}"
            fallocate -l 1G ${BATS_TEST_TMPDIR}/encrypted
            echo -n "${password}" | cryptsetup luksFormat -q --type ${luksVersion} ${BATS_TEST_TMPDIR}/encrypted -
            echo -n "${password}" | ${lukstool} checkpw --password-fd 0 ${BATS_TEST_TMPDIR}/encrypted
            rm -f ${BATS_TEST_TMPDIR}/encrypted
            echo password: "${password}" version: "${luksVersion}" ok
        done
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

@test passwords-defaults {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        for luksVersion in "" "--luks1" ; do
            echo password: "${password}"
            echo version: "${luksVersion}"
            echo -n "${password}" | ${lukstool} create --password-fd 0 ${luksVersion} ${BATS_TEST_TMPDIR}/plaintext ${BATS_TEST_TMPDIR}/encrypted
            echo -n "${password}" | cryptsetup -q --test-passphrase --key-file - luksOpen ${BATS_TEST_TMPDIR}/encrypted
            rm -f ${BATS_TEST_TMPDIR}/encrypted
            echo password: "${password}" version: "${luksVersion}" ok
        done
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}
