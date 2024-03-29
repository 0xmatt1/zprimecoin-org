#!/bin/bash
set -u


DATADIR=./benchmark-datadir
SHA256CMD="$(command -v sha256sum || echo shasum)"
SHA256ARGS="$(command -v sha256sum >/dev/null || echo '-a 256')"

function zprime_rpc {
    ./src/zprime-cli -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 "$@"
}

function zprime_rpc_slow {
    # Timeout of 1 hour
    zprime_rpc -rpcclienttimeout=3600 "$@"
}

function zprime_rpc_veryslow {
    # Timeout of 2.5 hours
    zprime_rpc -rpcclienttimeout=9000 "$@"
}

function zprime_rpc_wait_for_start {
    zprime_rpc -rpcwait getinfo > /dev/null
}

function zprimed_generate {
    zprime_rpc generate 101 > /dev/null
}

function extract_benchmark_datadir {
    if [ -f "$1.tar.xz" ]; then
        # Check the hash of the archive:
        "$SHA256CMD" $SHA256ARGS -c <<EOF
$2  $1.tar.xz
EOF
        ARCHIVE_RESULT=$?
    else
        echo "$1.tar.xz not found."
        ARCHIVE_RESULT=1
    fi
    if [ $ARCHIVE_RESULT -ne 0 ]; then
        zprimed_stop
        echo
        echo "Please download it and place it in the base directory of the repository."
        exit 1
    fi
    xzcat "$1.tar.xz" | tar x
}

function use_200k_benchmark {
    rm -rf benchmark-200k-UTXOs
    extract_benchmark_datadir benchmark-200k-UTXOs dc8ab89eaa13730da57d9ac373c1f4e818a37181c1443f61fd11327e49fbcc5e
    DATADIR="./benchmark-200k-UTXOs/node$1"
}

function zprimed_start {
    case "$1" in
        sendtoaddress|loadwallet|listunspent)
            case "$2" in
                200k-recv)
                    use_200k_benchmark 0
                    ;;
                200k-send)
                    use_200k_benchmark 1
                    ;;
                *)
                    echo "Bad arguments to zprimed_start."
                    exit 1
            esac
            ;;
        *)
            rm -rf "$DATADIR"
            mkdir -p "$DATADIR/regtest"
            touch "$DATADIR/zprime.conf"
    esac
    ./src/zprimed -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    ZPRIMED_PID=$!
    zprime_rpc_wait_for_start
}

function zprimed_stop {
    zprime_rpc stop > /dev/null
    wait $ZPRIMED_PID
}

function zprimed_massif_start {
    case "$1" in
        sendtoaddress|loadwallet|listunspent)
            case "$2" in
                200k-recv)
                    use_200k_benchmark 0
                    ;;
                200k-send)
                    use_200k_benchmark 1
                    ;;
                *)
                    echo "Bad arguments to zprimed_massif_start."
                    exit 1
            esac
            ;;
        *)
            rm -rf "$DATADIR"
            mkdir -p "$DATADIR/regtest"
            touch "$DATADIR/zprime.conf"
    esac
    rm -f massif.out
    valgrind --tool=massif --time-unit=ms --massif-out-file=massif.out ./src/zprimed -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    ZPRIMED_PID=$!
    zprime_rpc_wait_for_start
}

function zprimed_massif_stop {
    zprime_rpc stop > /dev/null
    wait $ZPRIMED_PID
    ms_print massif.out
}

function zprimed_valgrind_start {
    rm -rf "$DATADIR"
    mkdir -p "$DATADIR/regtest"
    touch "$DATADIR/zprime.conf"
    rm -f valgrind.out
    valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/zprimed -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    ZPRIMED_PID=$!
    zprime_rpc_wait_for_start
}

function zprimed_valgrind_stop {
    zprime_rpc stop > /dev/null
    wait $ZPRIMED_PID
    cat valgrind.out
}

function extract_benchmark_data {
    if [ -f "block-107134.tar.xz" ]; then
        # Check the hash of the archive:
        "$SHA256CMD" $SHA256ARGS -c <<EOF
4bd5ad1149714394e8895fa536725ed5d6c32c99812b962bfa73f03b5ffad4bb  block-107134.tar.xz
EOF
        ARCHIVE_RESULT=$?
    else
        echo "block-107134.tar.xz not found."
        ARCHIVE_RESULT=1
    fi
    if [ $ARCHIVE_RESULT -ne 0 ]; then
        zprimed_stop
        echo
        echo "Please generate it using qa/zprime/create_benchmark_archive.py"
        echo "and place it in the base directory of the repository."
        echo "Usage details are inside the Python script."
        exit 1
    fi
    xzcat block-107134.tar.xz | tar x -C "$DATADIR/regtest"
}


if [ $# -lt 2 ]
then
    echo "$0 : At least two arguments are required!"
    exit 1
fi

# Precomputation
case "$1" in
    *)
        case "$2" in
            verifyjoinsplit)
                zprimed_start "${@:2}"
                RAWJOINSPLIT=$(zprime_rpc zcsamplejoinsplit)
                zprimed_stop
        esac
esac

case "$1" in
    time)
        zprimed_start "${@:2}"
        case "$2" in
            sleep)
                zprime_rpc zcbenchmark sleep 10
                ;;
            parameterloading)
                zprime_rpc zcbenchmark parameterloading 10
                ;;
            createsaplingspend)
                zprime_rpc zcbenchmark createsaplingspend 10
                ;;
            verifysaplingspend)
                zprime_rpc zcbenchmark verifysaplingspend 1000
                ;;
            createsaplingoutput)
                zprime_rpc zcbenchmark createsaplingoutput 50
                ;;
            verifysaplingoutput)
                zprime_rpc zcbenchmark verifysaplingoutput 1000
                ;;
            createjoinsplit)
                zprime_rpc zcbenchmark createjoinsplit 10 "${@:3}"
                ;;
            verifyjoinsplit)
                zprime_rpc zcbenchmark verifyjoinsplit 1000 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                zprime_rpc_slow zcbenchmark solveequihash 50 "${@:3}"
                ;;
            verifyequihash)
                zprime_rpc zcbenchmark verifyequihash 1000
                ;;
            validatelargetx)
                zprime_rpc zcbenchmark validatelargetx 10 "${@:3}"
                ;;
            trydecryptnotes)
                zprime_rpc zcbenchmark trydecryptnotes 1000 "${@:3}"
                ;;
            incnotewitnesses)
                zprime_rpc zcbenchmark incnotewitnesses 100 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                zprime_rpc zcbenchmark connectblockslow 10
                ;;
            sendtoaddress)
                zprime_rpc zcbenchmark sendtoaddress 10 "${@:4}"
                ;;
            loadwallet)
                zprime_rpc zcbenchmark loadwallet 10
                ;;
            listunspent)
                zprime_rpc zcbenchmark listunspent 10
                ;;
            *)
                zprimed_stop
                echo "Bad arguments to time."
                exit 1
        esac
        zprimed_stop
        ;;
    memory)
        zprimed_massif_start "${@:2}"
        case "$2" in
            sleep)
                zprime_rpc zcbenchmark sleep 1
                ;;
            parameterloading)
                zprime_rpc zcbenchmark parameterloading 1
                ;;
            createsaplingspend)
                zprime_rpc zcbenchmark createsaplingspend 1
                ;;
            verifysaplingspend)
                zprime_rpc zcbenchmark verifysaplingspend 1
                ;;
            createsaplingoutput)
                zprime_rpc zcbenchmark createsaplingoutput 1
                ;;
            verifysaplingoutput)
                zprime_rpc zcbenchmark verifysaplingoutput 1
                ;;
            createjoinsplit)
                zprime_rpc_slow zcbenchmark createjoinsplit 1 "${@:3}"
                ;;
            verifyjoinsplit)
                zprime_rpc zcbenchmark verifyjoinsplit 1 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                zprime_rpc_slow zcbenchmark solveequihash 1 "${@:3}"
                ;;
            verifyequihash)
                zprime_rpc zcbenchmark verifyequihash 1
                ;;
            validatelargetx)
                zprime_rpc zcbenchmark validatelargetx 1
                ;;
            trydecryptnotes)
                zprime_rpc zcbenchmark trydecryptnotes 1 "${@:3}"
                ;;
            incnotewitnesses)
                zprime_rpc zcbenchmark incnotewitnesses 1 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                zprime_rpc zcbenchmark connectblockslow 1
                ;;
            sendtoaddress)
                zprime_rpc zcbenchmark sendtoaddress 1 "${@:4}"
                ;;
            loadwallet)
                # The initial load is sufficient for measurement
                ;;
            listunspent)
                zprime_rpc zcbenchmark listunspent 1
                ;;
            *)
                zprimed_massif_stop
                echo "Bad arguments to memory."
                exit 1
        esac
        zprimed_massif_stop
        rm -f massif.out
        ;;
    valgrind)
        zprimed_valgrind_start
        case "$2" in
            sleep)
                zprime_rpc zcbenchmark sleep 1
                ;;
            parameterloading)
                zprime_rpc zcbenchmark parameterloading 1
                ;;
            createsaplingspend)
                zprime_rpc zcbenchmark createsaplingspend 1
                ;;
            verifysaplingspend)
                zprime_rpc zcbenchmark verifysaplingspend 1
                ;;
            createsaplingoutput)
                zprime_rpc zcbenchmark createsaplingoutput 1
                ;;
            verifysaplingoutput)
                zprime_rpc zcbenchmark verifysaplingoutput 1
                ;;
            createjoinsplit)
                zprime_rpc_veryslow zcbenchmark createjoinsplit 1 "${@:3}"
                ;;
            verifyjoinsplit)
                zprime_rpc zcbenchmark verifyjoinsplit 1 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                zprime_rpc_veryslow zcbenchmark solveequihash 1 "${@:3}"
                ;;
            verifyequihash)
                zprime_rpc zcbenchmark verifyequihash 1
                ;;
            trydecryptnotes)
                zprime_rpc zcbenchmark trydecryptnotes 1 "${@:3}"
                ;;
            incnotewitnesses)
                zprime_rpc zcbenchmark incnotewitnesses 1 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                zprime_rpc zcbenchmark connectblockslow 1
                ;;
            *)
                zprimed_valgrind_stop
                echo "Bad arguments to valgrind."
                exit 1
        esac
        zprimed_valgrind_stop
        rm -f valgrind.out
        ;;
    valgrind-tests)
        case "$2" in
            gtest)
                rm -f valgrind.out
                valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/zprime-gtest
                cat valgrind.out
                rm -f valgrind.out
                ;;
            test_bitcoin)
                rm -f valgrind.out
                valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/test/test_bitcoin
                cat valgrind.out
                rm -f valgrind.out
                ;;
            *)
                echo "Bad arguments to valgrind-tests."
                exit 1
        esac
        ;;
    *)
        echo "Invalid benchmark type."
        exit 1
esac

# Cleanup
rm -rf "$DATADIR"
