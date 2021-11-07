#!/bin/sh
set -xe

user=ipfs

if [ `id -u` -eq 0 ]; then
  if [ ! -f "/data/ipfs" ]; then
    mkdir -p /data/ipfs
    chmod 777 /data/ipfs
  fi

  if [ ! -f "/export" ]; then
    mkdir -p /export
    chmod 777 /export
  fi

  echo "Changing user to $user"
  # restart script with new privileges
  exec su-exec "$user" "$0" "$@"
fi

if [ ! -f "/data/ipfs/config" ]; then
  ipfs init --profile test
  ipfs config profile apply test
  ipfs config --json Swarm.AddrFilters "[\"/ip4/0.0.0.0/ipcidr/0\", \"/ip6/::/ipcidr/0\"]"
  ipfs config --json Addresses.Swarm "[]"
  ipfs config --json Addresses.Announce "[]"
  ipfs config --json Addresses.NoAnnounce "[\"/ip4/0.0.0.0/ipcidr/0\", \"/ip6/::/ipcidr/0\"]"
  ipfs config Addresses.API "/ip4/0.0.0.0/tcp/5001"
  ipfs config Addresses.Gateway "/ip4/0.0.0.0/tcp/8080"
fi

ipfs config show
exec /usr/local/bin/start_ipfs "$@"
