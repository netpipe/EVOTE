#!/bin/bash

Q=17
N=8

random_poly() {
    local name=$1
    for ((i=0; i<N; i++)); do
        eval "$name[$i]=$(( RANDOM % Q ))"  # Full mod-Q integer
    done
}

encode_char() {
    local name=$1
    local char=$2
    local val=$(printf "%d" "'$char")
    for ((i=0; i<8; i++)); do
        bit=$(( (val >> i) & 1 ))
        eval "$name[$i]=$bit"
    done
}

decode_char() {
    local name=$1
    local val=0
    for ((i=0; i<8; i++)); do
        bit=$(eval echo \${$name[$i]})
        val=$(( val | (bit << i) ))
    done
    printf "%b" "$(printf '\\x%02x' "$val")"
}

encrypt_decrypt_char() {
    local char=$1
    encode_char m "$char"

    zero_poly e1
    zero_poly e2
    random_poly r

    for ((i=0;i<N;i++)); do
        u[$i]=$(( (a[$i]*r[$i] + e1[$i] + Q) % Q ))
        m_enc[$i]=$(( m[$i] ? Q/2 : 0 ))
        v[$i]=$(( (b[$i]*r[$i] + e2[$i] + m_enc[$i] + Q) % Q ))
    done

    for ((i=0;i<N;i++)); do
        us[$i]=$(( (u[$i]*s[$i]) % Q ))
        mprime[$i]=$(( (v[$i] - us[$i] + Q) % Q ))
        mdec[$i]=$(( mprime[$i] >= Q/2 ? 1 : 0 ))
    done

    decode_char mdec
}

zero_poly() {
    local name=$1
    for ((i=0; i<N; i++)); do
        eval "$name[$i]=0"
    done
}

main() {
    message="TESTING"
    echo "Original: $message"

    # One-time keygen
    random_poly a
    random_poly s
    zero_poly e   # No noise for reliable output

    for ((i=0;i<N;i++)); do
        b[$i]=$(( (a[$i]*s[$i] + e[$i] + Q) % Q ))
    done

    echo ""
    echo "Public key:"
    echo "  a = (${a[*]})"
    echo "  b = (${b[*]})"
    echo "Private key:"
    echo "  s = (${s[*]})"
    echo ""

    result=""
    for ((i=0; i<${#message}; i++)); do
        ch=${message:$i:1}
        decrypted=$(encrypt_decrypt_char "$ch")
        result+=$decrypted
    done

    echo "Decrypted: $result"
}


main
