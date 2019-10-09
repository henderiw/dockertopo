# dockertopo

go get -u "github.com/henderiw/dockertopo"
go build

./dockertopo -t /root/go/src/github.com/henderiw/dockertopo/leaf-spine.yaml -o destroy
./dockertopo -t /root/go/src/github.com/henderiw/dockertopo/leaf-spine.yaml