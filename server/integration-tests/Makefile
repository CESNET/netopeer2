DOCKER_NAME := netopeer2-integration-test-env
INTEGRATION_TEST_DIR ?= $(shell pwd)
DOCKER_RUN := docker run -it --rm -v $(INTEGRATION_TEST_DIR):/local -v $(INTEGRATION_TEST_DIR)/build/log:/var/log -w /local/tests --privileged $(DOCKER_NAME)

PYTEST_ARGS ?= -x

.PHONY: test build

test: build/docker_built
	$(DOCKER_RUN) py.test -vvl $(PYTEST_ARGS) ; \
	_PYTEST_EXIT_CODE=$$? ; \
	$(DOCKER_RUN) chown -R $(shell id -u):$(shell id -g) /var/log ; \
	exit $$_PYTEST_EXIT_CODE

format: build/docker_built
	$(DOCKER_RUN) black .
	$(DOCKER_RUN) /bin/sh -c 'find ../test-service \( -name "*.hpp" -o -name "*.cpp" \) | xargs clang-format -i'
	$(DOCKER_RUN) chown -R $(shell id -u):$(shell id -g) ../test-service

build: build/docker_built

build/docker_built: Dockerfile repo $(shell find repo -type f) $(shell find yang -type f) $(shell find support -type f) $(shell find test-service -type f)
	mkdir -p build/log/supervisor
	docker build -t $(DOCKER_NAME) .
	touch $@

repo:
	mkdir -p repo
	cd repo && \
	    git clone -b devel https://github.com/CESNET/libyang.git && \
	    git clone -b devel https://github.com/CESNET/libnetconf2.git && \
	    git clone -b devel https://github.com/sysrepo/sysrepo.git && \
	    git clone -b devel-server https://github.com/CESNET/Netopeer2.git
	@echo
	@echo libyang revision: $$(cd repo/libyang && git rev-parse HEAD)
	@echo libnetconf2 revision: $$(cd repo/libnetconf2 && git rev-parse HEAD)
	@echo sysrepo revision: $$(cd repo/sysrepo && git rev-parse HEAD)
	@echo Netopeer2 revision: $$(cd repo/Netopeer2 && git rev-parse HEAD)
	@echo