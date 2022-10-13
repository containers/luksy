#!/usr/bin/env bats

lukstool=${LUKSTOOL:-${BATS_TEST_DIRNAME}/../lukstool}

function passwords() {
    dd if=/dev/urandom bs=1M count=64 of=${BATS_TEST_TMPDIR}/plaintext status=none
    for password in short morethaneight morethansixteenchars ; do
        echo -n "${password}" | ${lukstool} encrypt --password-fd 0 "$@" ${BATS_TEST_TMPDIR}/plaintext ${BATS_TEST_TMPDIR}/encrypted
        echo -n "${password}" | cryptsetup -q --test-passphrase --key-file - luksOpen ${BATS_TEST_TMPDIR}/encrypted
        rm -f ${BATS_TEST_TMPDIR}/encrypted
    done
    rm -f ${BATS_TEST_TMPDIR}/plaintext
}

@test passwords-defaults-luks1 {
    passwords --luks1
}

@test passwords-defaults-luks2 {
    passwords
}

@test passwords-aes-xts-plain32-luks1 {
    passwords --cipher aes-xts-plain --luks1
}

@test passwords-aes-xts-plain32-luks2 {
    passwords --cipher aes-xts-plain
}

@test passwords-aes-xts-plain64-luks1 {
    passwords --cipher aes-xts-plain64 --luks1
}

@test passwords-aes-xts-plain64-luks2 {
    passwords --cipher aes-xts-plain64
}

@test passwords-aes-cbc-plain32-luks1 {
    passwords --cipher aes-cbc-plain --luks1
}

@test passwords-aes-cbc-plain32-luks2 {
    passwords --cipher aes-cbc-plain
}

@test passwords-aes-cbc-plain64-luks1 {
    passwords --cipher aes-cbc-plain64 --luks1
}

@test passwords-aes-cbc-plain64-luks2 {
    passwords --cipher aes-cbc-plain64
}

@test passwords-aes-cbc-essiv:sha256-luks1 {
    passwords --cipher aes-cbc-essiv:sha256 --luks1
}

@test passwords-aes-cbc-essiv:sha256-luks2 {
    passwords --cipher aes-cbc-essiv:sha256
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
