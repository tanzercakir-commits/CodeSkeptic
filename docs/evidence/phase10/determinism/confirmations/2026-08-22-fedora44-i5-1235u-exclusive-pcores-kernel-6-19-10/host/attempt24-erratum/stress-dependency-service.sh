#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin
export LC_ALL=C
export LANG=C
umask 077
unset BASH_ENV ENV CDPATH

readonly marker=/run/user/1000/codeskeptic-attempt24-manager-live
readonly order=/run/user/1000/codeskeptic-attempt24-stop-order

case ${1:-} in
  backend-start|consumer-start)
    exec /usr/bin/sleep infinity
    ;;
  manager-start)
    /usr/bin/install -m 0600 /dev/null "$marker"
    exec /usr/bin/sleep infinity
    ;;
  consumer-stop)
    printf 'consumer\n' >> "$order"
    ;;
  manager-stop)
    printf 'manager\n' >> "$order"
    /usr/bin/rm -f -- "$marker"
    ;;
  backend-stop)
    [[ ! -e $marker && ! -L $marker ]]
    printf 'backend\n' >> "$order"
    ;;
  *)
    exit 2
    ;;
esac
