#/bin/bash

export OPENVSX_VERSION=`curl -sSL https://api.github.com/repos/teknolojikpanda/openvsx/releases/latest | jq -r ".tag_name"`
docker buildx build -t "teknolojikpanda/openvsx:$OPENVSX_VERSION" --build-arg "OPENVSX_VERSION=$OPENVSX_VERSION" .
