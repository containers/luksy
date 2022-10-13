#!/usr/bin/env bats

lukstool=${LUKSTOOL:-${BATS_TEST_DIRNAME}/../lukstool}

@test passwords-defaults {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        for luksVersion in "" "--luks1" ; do
            echo testing password: "${password}" + version "'${luksVersion}'"
            echo -n "${password}" | ${lukstool} encrypt --password-fd 0 ${luksVersion} ${BATS_TEST_TMPDIR}/plaintext ${BATS_TEST_TMPDIR}/encrypted
            echo -n "${password}" | cryptsetup -q --test-passphrase --key-file - luksOpen ${BATS_TEST_TMPDIR}/encrypted
            rm -f ${BATS_TEST_TMPDIR}/encrypted
            echo password: "${password}" + version: "$'{luksVersion}'" ok
        done
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

function passwords_cryptsetup() {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        echo testing password: "${password}"
        fallocate -l 1G ${BATS_TEST_TMPDIR}/encrypted
        echo -n "${password}" | cryptsetup luksFormat -q "$@" ${BATS_TEST_TMPDIR}/encrypted -
        echo -n "${password}" | ${lukstool} decrypt --password-fd 0 ${BATS_TEST_TMPDIR}/encrypted
        rm -f ${BATS_TEST_TMPDIR}/encrypted
        echo password: "${password}" ok
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

@test passwords-cryptsetup-defaults-luks1 {
    passwords_cryptsetup --type luks1
}

@test passwords-cryptsetup-defaults-luks2 {
    passwords_cryptsetup --type luks2
}

@test passwords-cryptsetup-aes-xts-plain32-luks1 {
    passwords_cryptsetup --cipher aes-xts-plain --type luks1
}

@test passwords-cryptsetup-aes-xts-plain32-luks2 {
    passwords_cryptsetup --cipher aes-xts-plain --type luks2
}

@test passwords-cryptsetup-aes-xts-plain64-luks1 {
    passwords_cryptsetup --cipher aes-xts-plain64 --type luks1
}

@test passwords-cryptsetup-aes-xts-plain64-luks2 {
    passwords_cryptsetup --cipher aes-xts-plain64 --type luks2
}

@test passwords-cryptsetup-aes-cbc-plain32-luks1 {
    passwords_cryptsetup --cipher aes-cbc-plain --type luks1
}

@test passwords-cryptsetup-aes-cbc-plain32-luks2 {
    passwords_cryptsetup --cipher aes-cbc-plain --type luks2
}

@test passwords-cryptsetup-aes-cbc-plain64-luks1 {
    passwords_cryptsetup --cipher aes-cbc-plain64 --type luks1
}

@test passwords-cryptsetup-aes-cbc-plain64-luks2 {
    passwords_cryptsetup --cipher aes-cbc-plain64 --type luks2
}

@test passwords-cryptsetup-aes-cbc-essiv:sha256-luks1 {
    passwords_cryptsetup --cipher aes-cbc-essiv:sha256 --type luks1
}

@test passwords-cryptsetup-aes-cbc-essiv:sha256-luks2 {
    passwords_cryptsetup --cipher aes-cbc-essiv:sha256 --type luks2
}
