# Convenience wrappers around the Docker mesh harness in test/net. The project
# itself is built with CMake (see README.md "Build"); these targets only drive
# the local network and the e2e gate so they come up in one command.
.PHONY: e2e localnet-up localnet-status localnet-down

# Build, converge, assert full discovery + dual-stack, tear down. Non-zero exit
# on failure - run this before cutting a release.
e2e:
	./test/net/e2e.sh

# A local, isolated four-node mesh for manual inspection.
localnet-up:
	./test/net/localnet.sh up

localnet-status:
	./test/net/localnet.sh status

localnet-down:
	./test/net/localnet.sh down
