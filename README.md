# dockertopo

go get -u "github.com/henderiw/dockertopo"

go build

#deploy a leaf spine topoly

./dockertopo -t /root/go/src/github.com/henderiw/dockertopo/leaf-spine.yaml

#destroy leaf/spine topology

./dockertopo -t /root/go/src/github.com/henderiw/dockertopo/leaf-spine.yaml -o destroy
